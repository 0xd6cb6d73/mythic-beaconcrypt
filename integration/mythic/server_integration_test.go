package main_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
	"github.com/google/uuid"
	"github.com/its-a-feature/Mythic/crypto/provider"
	"github.com/its-a-feature/Mythic/database"
	"github.com/its-a-feature/Mythic/logging"
	"github.com/its-a-feature/Mythic/rabbitmq"
	"github.com/its-a-feature/Mythic/utils"
	"github.com/its-a-feature/Mythic/webserver"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	amqp "github.com/rabbitmq/amqp091-go"
)

// This test is injected into a private copy of the pinned Mythic source by the
// provider's integration script. Mythic uses its real production initializers,
// routes, RPC listeners, and migrations in this process, so administrative calls
// share the server's transient authorization-token store. The provider runs as
// its production executable; every exchange uses real HTTP, AMQP, and PostgreSQL.
func TestBeaconcryptMythicE2E(t *testing.T) {
	providerBinary := requiredE2EEnv(t, "BEACONCRYPT_TEST_PROVIDER_BINARY")
	brokerURL := requiredE2EEnv(t, "BEACONCRYPT_AMQP_TEST_URL")
	adminDSN := requiredE2EEnv(t, "CRYPTO_PROVIDER_TEST_DSN")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	dsn := isolatedE2EDatabase(t, adminDSN)
	httpPort, grpcPort := freeE2EPort(t), freeE2EPort(t)
	providerName := "beaconcrypt-e2e-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	env := e2eServerEnvironment(t, dsn, brokerURL)
	env["MYTHIC_SERVER_PORT"], env["MYTHIC_SERVER_GRPC_PORT"] = strconv.Itoa(httpPort), strconv.Itoa(grpcPort)
	env["MYTHIC_SERVER_BIND_LOCALHOST_ONLY"], env["MYTHIC_DOCKER_NETWORKING"] = "true", "host"
	env["MYTHIC_SERVER_DYNAMIC_PORTS"] = "0"
	env["MYTHIC_ADMIN_USER"], env["MYTHIC_ADMIN_PASSWORD"] = "beaconcrypt_e2e_admin", "isolated-integration-password"
	env["DEFAULT_OPERATION_NAME"], env["JWT_SECRET"] = "Beaconcrypt integration", strings.Repeat("e", 48)
	env["DEBUG_LEVEL"], env["MYTHIC_DEBUG_AGENT_MESSAGE"] = "warning", "false"
	env["MYTHIC_SERVER_ALLOW_WEBHOOKS_ON_NEW_CALLBACKS"] = "false"
	for key, value := range env {
		t.Setenv(key, value)
	}
	// Keep the same startup order as Mythic's main. Calling its public profile
	// helpers in this process must use the real server's auth-context token store.
	utils.Initialize()
	logging.Initialize()
	database.Initialize()
	router := webserver.Initialize()
	rabbitmq.Initialize()
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: 15 * time.Second}
	endpoint := server.URL
	awaitE2E(t, ctx, nil, func() bool {
		response, err := client.Get(endpoint + "/health")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	}, "actual Mythic HTTP/DB/AMQP startup")
	db := database.DB
	t.Cleanup(func() { _ = db.Close() })
	var operationID, operatorID int
	var err error
	if err := db.Get(&operationID, `SELECT id FROM operation WHERE name=$1`, env["DEFAULT_OPERATION_NAME"]); err != nil {
		t.Fatal(err)
	}
	if err := db.Get(&operatorID, `SELECT id FROM operator WHERE username=$1`, env["MYTHIC_ADMIN_USER"]); err != nil {
		t.Fatal(err)
	}
	providerEnv := map[string]string{"RABBITMQ_URL": brokerURL, "BEACONCRYPT_PROVIDER_NAME": providerName, "BEACONCRYPT_NAMESPACE": "beaconcrypt-e2e", "BEACONCRYPT_STATE_ID": "server", "BEACONCRYPT_RPC_TIMEOUT": "20s", "DEBUG_LEVEL": "warning"}
	providerProcess := startE2EProcess(t, ctx, providerBinary, nil, providerEnv)
	waitE2EProviderReady(t, ctx, brokerURL, providerProcess, providerName)
	awaitE2E(t, ctx, providerProcess, func() bool {
		var running bool
		return db.Get(&running, `SELECT container_running FROM consuming_container WHERE name=$1 AND type='crypto' AND NOT deleted`, providerName) == nil && running
	}, "actual provider capability registration")
	var stateCount int
	if err = db.Get(&stateCount, `SELECT count(*) FROM crypto_provider_state s JOIN consuming_container c ON c.id=s.provider_id WHERE c.name=$1`, providerName); err != nil || stateCount != 0 {
		t.Fatalf("provider startup must not create a shared campaign owner: count=%d err=%v", stateCount, err)
	}
	auth := rabbitmq.RabbitMQAuthContext{OperationID: operationID, OperatorID: operatorID}
	keys, err := rabbitmq.PrepareCryptoProviderKeys("provider:"+providerName+":beaconcrypt", operationID, auth)
	if err != nil {
		t.Fatal(err)
	}
	if keys.BindingID == nil {
		t.Fatal("actual Mythic did not persist provider profile binding")
	}
	parentConnection, err := rabbitmq.RabbitMQConnection.GetConnection()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parentConnection.CloseDeadline(time.Now().Add(time.Second)) })
	profile := loadE2EProfile(t, db, *keys.BindingID)
	kid, material := profile.kid, profile.material
	if profile.stateID != "server/campaign/"+strconv.Itoa(operationID) {
		t.Fatalf("profile did not select its campaign owner: state_id=%q", profile.stateID)
	}
	firstBeforeOtherCampaign := loadE2EState(t, db, providerName, profile.namespace, profile.stateID)
	var otherOperationID int
	if err = db.QueryRow(`INSERT INTO operation(name,admin_id) VALUES($1,$2) RETURNING id`, "Beaconcrypt isolated campaign", operatorID).Scan(&otherOperationID); err != nil {
		t.Fatal(err)
	}
	otherAuth := rabbitmq.RabbitMQAuthContext{OperationID: otherOperationID, OperatorID: operatorID}
	otherKeys, err := rabbitmq.PrepareCryptoProviderKeys("provider:"+providerName+":beaconcrypt", otherOperationID, otherAuth)
	if err != nil || otherKeys.BindingID == nil {
		t.Fatalf("second campaign profile preparation failed: %v", err)
	}
	otherProfile := loadE2EProfile(t, db, *otherKeys.BindingID)
	if otherProfile.stateID != "server/campaign/"+strconv.Itoa(otherOperationID) || profile.namespace != otherProfile.namespace || profile.stateID == otherProfile.stateID || bytes.Equal(material.ServerPublicKey, otherProfile.material.ServerPublicKey) {
		t.Fatal("campaigns must have distinct stored owners and native server identities")
	}
	otherInitial := loadE2EState(t, db, providerName, otherProfile.namespace, otherProfile.stateID)
	if bytes.Equal(firstBeforeOtherCampaign.stateBlob, otherInitial.stateBlob) {
		t.Fatal("campaigns shared their native checkpoint")
	}
	if err = db.Get(&stateCount, `SELECT count(*) FROM crypto_provider_state s JOIN consuming_container c ON c.id=s.provider_id WHERE c.name=$1`, providerName); err != nil || stateCount != 2 {
		t.Fatalf("expected one native owner per campaign: count=%d err=%v", stateCount, err)
	}
	assertE2EStateUnchanged(t, db, providerName, profile.namespace, profile.stateID, firstBeforeOtherCampaign)
	// Independent builds in the same campaign share its native owner.
	sameCampaignKeys, err := rabbitmq.PrepareCryptoProviderKeys("provider:"+providerName+":beaconcrypt", operationID, auth)
	if err != nil || sameCampaignKeys.BindingID == nil {
		t.Fatalf("same-campaign profile preparation failed: %v", err)
	}
	sameCampaignProfile := loadE2EProfile(t, db, *sameCampaignKeys.BindingID)
	if sameCampaignProfile.stateID != profile.stateID || !bytes.Equal(sameCampaignProfile.material.ServerPublicKey, material.ServerPublicKey) || sameCampaignProfile.profileRef == profile.profileRef {
		t.Fatal("builds in one campaign must share an owner while retaining distinct profiles")
	}
	payloadID, payloadUUID, c2Name := seedE2EPayload(t, db, operationID, operatorID, providerName, *keys.BindingID)
	first := registerE2EClient(t, ctx, client, endpoint, c2Name, payloadUUID, kid, material.ServerPublicKey)
	second := registerE2EClient(t, ctx, client, endpoint, c2Name, payloadUUID, kid, material.ServerPublicKey)
	if first.callbackUUID == second.callbackUUID {
		t.Fatal("independent clients shared a callback")
	}
	for _, session := range []*e2eAgent{first, second} {
		var boundPayload int
		var binding string
		if err = db.QueryRow(`SELECT registered_payload_id,crypto_provider_binding_id FROM callback WHERE agent_callback_id=$1`, session.callbackUUID).Scan(&boundPayload, &binding); err != nil || boundPayload != payloadID || binding != session.stageUUID {
			t.Fatalf("real callback/session transition failed: %v", err)
		}
	}
	_, otherPayloadUUID, otherC2Name := seedE2EPayload(t, db, otherOperationID, operatorID, providerName, *otherKeys.BindingID)
	otherFirst := registerE2EClient(t, ctx, client, endpoint, otherC2Name, otherPayloadUUID, otherProfile.kid, otherProfile.material.ServerPublicKey)
	otherSecond := registerE2EClient(t, ctx, client, endpoint, otherC2Name, otherPayloadUUID, otherProfile.kid, otherProfile.material.ServerPublicKey)
	otherBeforeFirstMessages := loadE2EState(t, db, providerName, otherProfile.namespace, otherProfile.stateID)
	blob := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0, 255, 128, 1, '\n', '{', '}', 42}, 8192))
	for i, tracking := range []string{"first poll", blob, "final poll before restart"} {
		reply := first.exchange(t, ctx, client, endpoint, c2Name, map[string]interface{}{"action": "get_tasking", "tasking_size": -1, "get_delegate_tasks": false, "tracking": tracking})
		if reply["action"] != "get_tasking" || reply["tracking"] != tracking {
			t.Fatalf("actual Mythic changed application message %d", i)
		}
	}
	updated := first.exchange(t, ctx, client, endpoint, c2Name, map[string]interface{}{"action": "update_info", "host": "updated-e2e-host", "user": "alice", "tracking": "updated-before-restart"})
	if updated["status"] != "success" || updated["tracking"] != "updated-before-restart" {
		t.Fatalf("actual update_info failed: %+v", updated)
	}
	var host string
	if err = db.Get(&host, `SELECT host FROM callback WHERE agent_callback_id=$1`, first.callbackUUID); err != nil || host != "UPDATED-E2E-HOST" {
		t.Fatalf("callback update did not reach PostgreSQL: host=%q err=%v", host, err)
	}
	assertE2EStateUnchanged(t, db, providerName, otherProfile.namespace, otherProfile.stateID, otherBeforeFirstMessages)
	assertE2ECampaignRejection(t, db, providerName, profile, otherProfile, first, operationID, otherOperationID)
	wrongScope := rabbitmq.MythicRPCCallbackEncryptBytes(rabbitmq.MythicRPCCallbackEncryptBytesMessage{AgentCallbackID: first.callbackUUID, C2Profile: c2Name, Message: []byte("cross-campaign input")}, otherAuth)
	if wrongScope.Success {
		t.Fatal("real Mythic accepted a callback operation from another campaign")
	}
	assertE2ECampaignCheckpointIsolation(t, ctx, db, providerProcess, client, endpoint, providerName, profile, otherProfile, first, otherFirst, c2Name, otherC2Name)
	// Both campaigns run multiple live agents concurrently; their checkpoints
	// must advance independently without mixing session identities or replies.
	// The normal serial Mythic storage consumer may serialize their storage RPCs.
	firstBeforeConcurrent := loadE2EState(t, db, providerName, profile.namespace, profile.stateID)
	otherBeforeConcurrent := loadE2EState(t, db, providerName, otherProfile.namespace, otherProfile.stateID)
	var exchanges sync.WaitGroup
	for i, item := range []struct {
		agent *e2eAgent
		c2    string
	}{{first, c2Name}, {second, c2Name}, {otherFirst, otherC2Name}, {otherSecond, otherC2Name}} {
		exchanges.Add(1)
		go func() {
			defer exchanges.Done()
			for message := 1; message <= 3; message++ {
				tracking := "campaign-agent-" + strconv.Itoa(i) + "-message-" + strconv.Itoa(message)
				reply := item.agent.exchange(t, ctx, client, endpoint, item.c2, map[string]interface{}{"action": "get_tasking", "tasking_size": -1, "get_delegate_tasks": false, "tracking": tracking})
				if reply["tracking"] != tracking {
					t.Error("concurrent campaign exchange changed application output")
					return
				}
			}
		}()
	}
	exchanges.Wait()
	if t.Failed() {
		return
	}
	assertE2EStateAdvanced(t, db, providerName, profile.namespace, profile.stateID, firstBeforeConcurrent)
	assertE2EStateAdvanced(t, db, providerName, otherProfile.namespace, otherProfile.stateID, otherBeforeConcurrent)
	assertE2EStore(t, db, providerName, 1)
	providerProcess.stop(t)
	waitE2EProviderQueuesReleased(t, ctx, brokerURL, providerName)
	restored := startE2EProcess(t, ctx, providerBinary, nil, providerEnv)
	waitE2EProviderReady(t, ctx, brokerURL, restored, providerName)
	// Staged check-in replay uses Mythic's own durable exchange ledger after its
	// staging row was consumed. Do not consume its old ciphertext twice locally.
	replay := postE2EFrame(t, ctx, client, endpoint, c2Name, first.stageUUID, first.checkinCiphertext)
	if !bytes.Equal(replay, first.checkinResponse) {
		t.Fatal("real Mythic did not replay exact committed staged check-in reply")
	}
	for _, session := range []*e2eAgent{first, second} {
		reply := session.exchange(t, ctx, client, endpoint, c2Name, map[string]interface{}{"action": "get_tasking", "tasking_size": -1, "get_delegate_tasks": false, "tracking": "same live client after provider restart", "binary": blob})
		if reply["tracking"] != "same live client after provider restart" || reply["binary"] != blob {
			t.Fatal("live client/server ratchets lost continuity after provider restart")
		}
	}
	for _, session := range []*e2eAgent{otherFirst, otherSecond} {
		reply := session.exchange(t, ctx, client, endpoint, otherC2Name, map[string]interface{}{"action": "get_tasking", "tasking_size": -1, "get_delegate_tasks": false, "tracking": "second campaign after restart"})
		if reply["tracking"] != "second campaign after restart" {
			t.Fatal("second campaign lost its native ratchets after provider restart")
		}
	}
	// Lazy restoration must retain each campaign's distinct native identity.
	for _, item := range []struct {
		operation int
		auth      rabbitmq.RabbitMQAuthContext
		profile   e2eProfile
	}{{operationID, auth, profile}, {otherOperationID, otherAuth, otherProfile}} {
		keys, err := rabbitmq.PrepareCryptoProviderKeys("provider:"+providerName+":beaconcrypt", item.operation, item.auth)
		if err != nil || keys.BindingID == nil {
			t.Fatalf("restored campaign profile failed: %v", err)
		}
		reloaded := loadE2EProfile(t, db, *keys.BindingID)
		if reloaded.stateID != item.profile.stateID || !bytes.Equal(reloaded.material.ServerPublicKey, item.profile.material.ServerPublicKey) {
			t.Fatal("campaign identity or state routing changed after restart")
		}
	}
	// Exercise Mythic's actual byte APIs too: these call the same real worker and
	// server-side PostgreSQL storage RPC, without treating arbitrary bytes as JSON.
	raw := bytes.Repeat([]byte{0, 255, 128, 1, '\n', '{', '}'}, 10240)
	encrypted := rabbitmq.MythicRPCCallbackEncryptBytes(rabbitmq.MythicRPCCallbackEncryptBytesMessage{AgentCallbackID: first.callbackUUID, C2Profile: c2Name, Message: raw}, auth)
	if !encrypted.Success {
		t.Fatal(encrypted.Error)
	}
	if plaintext, err := first.client.DecryptServerMessage(encrypted.Message); err != nil || !bytes.Equal(plaintext, raw) {
		t.Fatalf("actual Mythic binary encrypt changed bytes: %v", err)
	}
	cipher, err := first.client.EncryptToServer(raw)
	if err != nil {
		t.Fatal(err)
	}
	decrypted := rabbitmq.MythicRPCCallbackDecryptBytes(rabbitmq.MythicRPCCallbackDecryptBytesMessage{AgentCallbackUUID: first.callbackUUID, C2Profile: c2Name, Message: &cipher}, auth)
	if !decrypted.Success || !bytes.Equal(decrypted.Message, raw) {
		t.Fatalf("actual Mythic binary decrypt failed: %s", decrypted.Error)
	}
	final := first.exchange(t, ctx, client, endpoint, c2Name, map[string]interface{}{"action": "get_tasking", "tasking_size": -1, "get_delegate_tasks": false, "tracking": "HTTP still works after binary APIs"})
	if final["tracking"] != "HTTP still works after binary APIs" {
		t.Fatal("HTTP/native state diverged after byte APIs")
	}
	assertE2EStore(t, db, providerName, 2)
	var callbacks, stages int
	if err = db.Get(&callbacks, `SELECT count(*) FROM callback WHERE registered_payload_id=$1`, payloadID); err != nil {
		t.Fatal(err)
	}
	if err = db.Get(&stages, `SELECT count(*) FROM staginginfo WHERE payload_id=$1`, payloadID); err != nil {
		t.Fatal(err)
	}
	if callbacks != 2 || stages != 0 {
		t.Fatalf("unexpected persisted lifecycle: callbacks=%d stages=%d", callbacks, stages)
	}
	restored.stop(t)
}

type e2eAgent struct {
	client                             *beaconcrypt.Beacon
	stageUUID, callbackUUID            string
	checkinCiphertext, checkinResponse []byte
}

func registerE2EClient(t *testing.T, ctx context.Context, httpClient *http.Client, endpoint, c2, payload string, kid uint64, publicKey []byte) *e2eAgent {
	t.Helper()
	client, err := beaconcrypt.NewBeacon(kid, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	registration, err := client.GenerateRegistration()
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.NewString()
	body, err := json.Marshal(map[string]string{"action": "staging", "session_id": sessionID, "data": base64.StdEncoding.EncodeToString(registration)})
	if err != nil {
		t.Fatal(err)
	}
	framed := postE2EFrame(t, ctx, httpClient, endpoint, c2, payload, body)
	if repeated := postE2EFrame(t, ctx, httpClient, endpoint, c2, payload, body); !bytes.Equal(repeated, framed) {
		t.Fatal("actual Mythic changed its registration replay")
	}
	outer := decodeE2EFrame(t, framed, payload)
	var staging struct {
		Action    string `json:"action"`
		UUID      string `json:"uuid"`
		SessionID string `json:"session_id"`
		Data      []byte `json:"data"`
	}
	if err = json.Unmarshal(outer, &staging); err != nil || staging.Action != "staging" || staging.SessionID != sessionID {
		t.Fatalf("invalid actual staging reply: %v", err)
	}
	authenticated, err := client.ProcessInitialMessage(staging.Data)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Action    string `json:"action"`
		Status    string `json:"status"`
		UUID      string `json:"uuid"`
		SessionID string `json:"session_id"`
	}
	if err = json.Unmarshal(authenticated, &claims); err != nil || claims.Action != "staging" || claims.Status != "success" || claims.UUID != staging.UUID || claims.SessionID != sessionID {
		t.Fatalf("native authenticated claims differ from Mythic stage: %v", err)
	}
	checkin, err := json.Marshal(map[string]interface{}{"action": "checkin", "uuid": payload, "host": "e2e-host", "user": "alice", "pid": 1234, "os": "linux", "architecture": "amd64", "ips": []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := client.EncryptToServer(checkin)
	if err != nil {
		t.Fatal(err)
	}
	response := postE2EFrame(t, ctx, httpClient, endpoint, c2, staging.UUID, cipher)
	plaintext, err := client.DecryptServerMessage(decodeE2EFrame(t, response, staging.UUID))
	if err != nil {
		t.Fatal(err)
	}
	var checked struct {
		Status string `json:"status"`
		ID     string `json:"id"`
	}
	if err = json.Unmarshal(plaintext, &checked); err != nil || checked.Status != "success" {
		t.Fatalf("actual Mythic check-in failed: %s %v", plaintext, err)
	}
	if id, err := uuid.Parse(checked.ID); err != nil || id.String() != checked.ID {
		t.Fatal("actual Mythic omitted callback UUID")
	}
	return &e2eAgent{client: client, stageUUID: staging.UUID, callbackUUID: checked.ID, checkinCiphertext: cipher, checkinResponse: response}
}
func (a *e2eAgent) exchange(t *testing.T, ctx context.Context, client *http.Client, endpoint, c2 string, message map[string]interface{}) map[string]interface{} {
	t.Helper()
	plain, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := a.client.EncryptToServer(plain)
	if err != nil {
		t.Fatal(err)
	}
	reply := postE2EFrame(t, ctx, client, endpoint, c2, a.callbackUUID, cipher)
	plaintext, err := a.client.DecryptServerMessage(decodeE2EFrame(t, reply, a.callbackUUID))
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]interface{}
	if err = json.Unmarshal(plaintext, &response); err != nil {
		t.Fatal(err)
	}
	return response
}
func postE2EFrame(t *testing.T, ctx context.Context, client *http.Client, endpoint, c2, route string, body []byte) []byte {
	t.Helper()
	framed := base64.StdEncoding.EncodeToString(append([]byte(route), body...))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/agent_message", strings.NewReader(framed))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("mythic", c2)
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("actual Mythic /agent_message returned HTTP %d (%s)", response.StatusCode, reply)
	}
	return reply
}
func decodeE2EFrame(t *testing.T, encoded []byte, expected string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil || len(raw) < 36 {
		t.Fatalf("invalid actual Mythic frame: %v", err)
	}
	if string(raw[:36]) != expected {
		t.Fatalf("actual Mythic returned outer UUID %q, expected %q", raw[:36], expected)
	}
	return raw[36:]
}

func seedE2EPayload(t *testing.T, db *sqlx.DB, operationID, operatorID int, providerName, bindingID string) (int, string, string) {
	t.Helper()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	payloadTypeName, c2Name := "e2e-agent-"+suffix, "e2e-c2-"+suffix
	var payloadTypeID, c2ID, parameterID, payloadID int
	queries := []struct {
		query  string
		args   []interface{}
		target *int
	}{
		{`INSERT INTO payloadtype(name,mythic_encrypts,message_format,message_uuid_length,container_running,supported_crypto_schemes) VALUES($1,true,'json',36,true,'["beaconcrypt"]'::jsonb) RETURNING id`, []interface{}{payloadTypeName}, &payloadTypeID},
		{`INSERT INTO c2profile(name,is_p2p,container_running) VALUES($1,false,true) RETURNING id`, []interface{}{c2Name}, &c2ID},
	}
	for _, query := range queries {
		if err := db.QueryRow(query.query, query.args...).Scan(query.target); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.QueryRow(`INSERT INTO c2profileparameters(c2_profile_id,description,name,crypto_type) VALUES($1,'integration crypto','crypto',true) RETURNING id`, c2ID).Scan(&parameterID); err != nil {
		t.Fatal(err)
	}
	payloadUUID := uuid.NewString()
	if err := db.QueryRow(`INSERT INTO payload(uuid,operator_id,payload_type_id,operation_id,build_container,build_phase,callback_alert,os,callback_allowed) VALUES($1,$2,$3,$4,$5,'success',false,'linux',true) RETURNING id`, payloadUUID, operatorID, payloadTypeID, operationID, payloadTypeName).Scan(&payloadID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO payloadc2profiles(payload_id,c2_profile_id) VALUES($1,$2)`, payloadID, c2ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO c2profileparametersinstance(c2_profile_parameters_id,c2_profile_id,value,payload_id,operation_id,crypto_provider_binding_id) VALUES($1,$2,$3,$4,$5,$6)`, parameterID, c2ID, "provider:"+providerName+":beaconcrypt", payloadID, operationID, bindingID); err != nil {
		t.Fatal(err)
	}
	return payloadID, payloadUUID, c2Name
}

type e2eProfileMaterial struct {
	Version         int    `json:"version"`
	ServerKID       string `json:"server_kid"`
	ServerPublicKey []byte `json:"server_public_key"`
}

type e2eProfile struct {
	namespace, stateID, profileRef string
	kid                            uint64
	material                       e2eProfileMaterial
}

func loadE2EProfile(t *testing.T, db *sqlx.DB, bindingID string) e2eProfile {
	t.Helper()
	var profile e2eProfile
	var material []byte
	if err := db.QueryRow(`SELECT namespace,state_id,profile_ref,agent_config FROM crypto_provider_binding WHERE id=$1`, bindingID).Scan(&profile.namespace, &profile.stateID, &profile.profileRef, &material); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(material, &profile.material); err != nil || profile.material.Version != 1 {
		t.Fatalf("invalid real profile material: %v", err)
	}
	var err error
	profile.kid, err = strconv.ParseUint(profile.material.ServerKID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

type e2eStoredState struct {
	stateBlob, providerJSON []byte
	epoch, revision         int64
}

func loadE2EState(t *testing.T, db *sqlx.DB, name, namespace, stateID string) e2eStoredState {
	t.Helper()
	var state e2eStoredState
	if err := db.QueryRow(`SELECT s.state_blob,s.provider_json,s.owner_epoch,s.revision FROM crypto_provider_state s JOIN consuming_container c ON c.id=s.provider_id WHERE c.name=$1 AND s.namespace=$2 AND s.state_id=$3`, name, namespace, stateID).Scan(&state.stateBlob, &state.providerJSON, &state.epoch, &state.revision); err != nil {
		t.Fatal(err)
	}
	return state
}

func assertE2EStateUnchanged(t *testing.T, db *sqlx.DB, name, namespace, stateID string, before e2eStoredState) {
	t.Helper()
	after := loadE2EState(t, db, name, namespace, stateID)
	if after.epoch != before.epoch || after.revision != before.revision || !bytes.Equal(after.stateBlob, before.stateBlob) || !bytes.Equal(after.providerJSON, before.providerJSON) {
		t.Fatal("another campaign's operation changed this campaign's persisted state")
	}
}

func assertE2EStateAdvanced(t *testing.T, db *sqlx.DB, name, namespace, stateID string, before e2eStoredState) {
	t.Helper()
	after := loadE2EState(t, db, name, namespace, stateID)
	if after.epoch != before.epoch || after.revision <= before.revision || bytes.Equal(after.stateBlob, before.stateBlob) {
		t.Fatal("campaign did not commit its own native ratchet changes")
	}
}

func assertE2ECampaignRejection(t *testing.T, db *sqlx.DB, name string, first, other e2eProfile, agent *e2eAgent, operationID, otherOperationID int) {
	t.Helper()
	var sessionRef string
	if err := db.Get(&sessionRef, `SELECT session_ref FROM crypto_provider_binding WHERE id=$1`, agent.stageUUID); err != nil {
		t.Fatal(err)
	}
	beforeFirst := loadE2EState(t, db, name, first.namespace, first.stateID)
	beforeOther := loadE2EState(t, db, name, other.namespace, other.stateID)
	for _, request := range []provider.Request{
		{OperationScopeID: otherOperationID, Method: provider.Seal, ProfileRef: first.profileRef, SessionRef: sessionRef, Namespace: first.namespace, StateID: first.stateID, Message: []byte("wrong campaign owner")},
		{OperationScopeID: otherOperationID, Method: provider.Seal, ProfileRef: first.profileRef, SessionRef: sessionRef, Namespace: other.namespace, StateID: other.stateID, Message: []byte("foreign profile and session")},
		{OperationScopeID: operationID, Method: provider.Seal, ProfileRef: first.profileRef, SessionRef: sessionRef, Namespace: other.namespace, StateID: other.stateID, Message: []byte("wrong state routing")},
	} {
		request.APIVersion, request.RequestID, request.Scheme = provider.APIVersion, uuid.NewString(), "beaconcrypt"
		token, err := rabbitmq.GenerateRabbitMQAuthContextToken(rabbitmq.RabbitMQAuthContext{OperationID: request.OperationScopeID, ContainerName: name})
		if err != nil {
			t.Fatal(err)
		}
		request.AuthContext = token
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		route, err := provider.RoutingKey(name)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := rabbitmq.RabbitMQConnection.SendRPCMessage(rabbitmq.MYTHIC_EXCHANGE, route, body, false, rabbitmq.RPC_RETRY_POLICY_RETRY_ON_TIMEOUT, amqp.Table{rabbitmq.MYTHIC_RABBITMQ_AUTH_CONTEXT_HEADER: token})
		rabbitmq.InvalidateRabbitMQAuthContextToken(token)
		if err != nil {
			t.Fatal(err)
		}
		var response provider.Response
		if err = json.Unmarshal(reply, &response); err != nil || response.APIVersion != request.APIVersion || response.RequestID != request.RequestID || response.OperationScopeID != request.OperationScopeID || response.AuthContext != token || response.Success || response.Error == nil || response.Error.Outcome != provider.OutcomeRejected || len(response.Message) != 0 {
			t.Fatalf("cross-campaign request was not definitively rejected: %+v err=%v", response.Error, err)
		}
	}
	assertE2EStateUnchanged(t, db, name, first.namespace, first.stateID, beforeFirst)
	assertE2EStateUnchanged(t, db, name, other.namespace, other.stateID, beforeOther)
}

func assertE2ECampaignCheckpointIsolation(t *testing.T, ctx context.Context, db *sqlx.DB, process *e2eProcess, client *http.Client, endpoint, name string, first, other e2eProfile, firstAgent, otherAgent *e2eAgent, firstC2, otherC2 string) {
	t.Helper()
	firstBefore := loadE2EState(t, db, name, first.namespace, first.stateID)
	otherBefore := loadE2EState(t, db, name, other.namespace, other.stateID)
	transaction, err := db.BeginTxx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback() }()
	var revision int64
	if err = transaction.Get(&revision, `SELECT s.revision FROM crypto_provider_state s JOIN consuming_container c ON c.id=s.provider_id WHERE c.name=$1 AND s.namespace=$2 AND s.state_id=$3 FOR UPDATE OF s`, name, first.namespace, first.stateID); err != nil {
		t.Fatal(err)
	}
	firstReply := make(chan map[string]interface{}, 1)
	defer func() {
		_ = transaction.Rollback()
		select {
		case <-firstReply:
		case <-time.After(5 * time.Second):
		}
	}()
	go func() {
		defer close(firstReply)
		firstReply <- firstAgent.exchange(t, ctx, client, endpoint, firstC2, map[string]interface{}{"action": "get_tasking", "tasking_size": -1, "get_delegate_tasks": false, "tracking": "campaign A waiting on its checkpoint"})
	}()
	// PostgreSQL confirms that the real provider has reached a storage mutation
	// blocked by this transaction, rather than relying on timing assumptions.
	awaitE2E(t, ctx, process, func() bool {
		var blocked int
		return db.Get(&blocked, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%crypto_provider_state%' AND pid<>pg_backend_pid()`) == nil && blocked > 0
	}, "campaign A checkpoint blocked by its real PostgreSQL row lock")
	// State ownership remains per campaign, but storage requests use Mythic's
	// ordinary serial RPC consumer. Do not require another campaign's storage
	// request to finish while this consumer is blocked by the database row lock.
	assertE2EStateUnchanged(t, db, name, first.namespace, first.stateID, firstBefore)
	assertE2EStateUnchanged(t, db, name, other.namespace, other.stateID, otherBefore)
	select {
	case <-firstReply:
		t.Fatal("campaign A completed despite its blocked checkpoint commit")
	default:
	}
	if err = transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case reply := <-firstReply:
		if reply["tracking"] != "campaign A waiting on its checkpoint" {
			t.Fatal("campaign A failed to resume after its checkpoint lock was released")
		}
	case <-ctx.Done():
		t.Fatal("campaign A did not resume after its checkpoint lock was released")
	}
	assertE2EStateAdvanced(t, db, name, first.namespace, first.stateID, firstBefore)
	assertE2EStateUnchanged(t, db, name, other.namespace, other.stateID, otherBefore)
	firstAfter := loadE2EState(t, db, name, first.namespace, first.stateID)
	otherReply := otherAgent.exchange(t, ctx, client, endpoint, otherC2, map[string]interface{}{"action": "get_tasking", "tasking_size": -1, "get_delegate_tasks": false, "tracking": "campaign B commits its own checkpoint"})
	if otherReply["tracking"] != "campaign B commits its own checkpoint" {
		t.Fatal("independent campaign changed its application reply")
	}
	assertE2EStateAdvanced(t, db, name, other.namespace, other.stateID, otherBefore)
	assertE2EStateUnchanged(t, db, name, first.namespace, first.stateID, firstAfter)
	t.Log("Real campaigns committed separate native checkpoints after the blocked storage request resumed")
}

func assertE2EStore(t *testing.T, db *sqlx.DB, name string, epoch int64) {
	t.Helper()
	var states []struct {
		Epoch    int64 `db:"owner_epoch"`
		Revision int64 `db:"revision"`
		Results  int64 `db:"results"`
	}
	if err := db.Select(&states, `SELECT s.owner_epoch,s.revision,(SELECT count(*) FROM crypto_provider_result r WHERE r.provider_id=s.provider_id AND r.namespace=s.namespace AND r.state_id=s.state_id) results FROM crypto_provider_state s JOIN consuming_container c ON c.id=s.provider_id WHERE c.name=$1`, name); err != nil || len(states) == 0 {
		t.Fatalf("actual campaign state missing: %v", err)
	}
	for _, state := range states {
		if state.Epoch != epoch || state.Revision != state.Results || state.Results < 5 {
			t.Fatalf("actual PostgreSQL campaign checkpoint/result journal mismatch: epoch=%d revision=%d results=%d", state.Epoch, state.Revision, state.Results)
		}
	}
	var authResults int
	if err := db.Get(&authResults, `SELECT count(*) FROM crypto_provider_result r JOIN consuming_container c ON c.id=r.provider_id WHERE c.name=$1 AND result ? 'auth_context'`, name); err != nil || authResults != 0 {
		t.Fatalf("transient auth persisted in real provider journal: %v", err)
	}
}

// A campaign owner is created or restored on its first request, so readiness
// probes the real worker queue rather than waiting for a global state record.
func waitE2EProviderReady(t *testing.T, ctx context.Context, address string, process *e2eProcess, name string) {
	t.Helper()
	connection, err := amqp.Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.CloseDeadline(time.Now().Add(time.Second)) }()
	awaitE2E(t, ctx, process, func() bool {
		channel, err := connection.Channel()
		if err != nil {
			return false
		}
		defer func() { _ = channel.Close() }()
		queue, err := channel.QueueDeclarePassive(name+"_crypto_provider_rpc", true, true, false, false, nil)
		var brokerError *amqp.Error
		// The SDK's exclusive queue cannot be inspected from this connection.
		// ResourceLocked confirms that the restarted process owns it.
		return err == nil && queue.Consumers > 0 || errors.As(err, &brokerError) && brokerError.Code == amqp.ResourceLocked
	}, "actual provider RPC queue readiness")
}

func requiredE2EEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required for real Mythic integration", name)
	}
	return value
}
func freeE2EPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
func isolatedE2EDatabase(t *testing.T, dsn string) string {
	t.Helper()
	admin, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "beaconcrypt_e2e_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE DATABASE ` + pq.QuoteIdentifier(name)); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE ` + pq.QuoteIdentifier(name) + ` WITH (FORCE)`); err != nil {
			t.Errorf("drop isolated integration database: %v", err)
		}
		_ = admin.Close()
	})
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme == "" {
		t.Fatal("real Mythic integration requires a PostgreSQL URL DSN")
	}
	parsed.Path = "/" + name
	return parsed.String()
}
func e2eServerEnvironment(t *testing.T, dsn, broker string) map[string]string {
	t.Helper()
	pg, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	rabbit, err := amqp.ParseURI(broker)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := pg.User.Password()
	pgPort := pg.Port()
	if pgPort == "" {
		pgPort = "5432"
	}
	return map[string]string{"POSTGRES_HOST": pg.Hostname(), "POSTGRES_PORT": pgPort, "POSTGRES_USER": pg.User.Username(), "POSTGRES_PASSWORD": password, "POSTGRES_DB": strings.TrimPrefix(pg.Path, "/"), "POSTGRES_SSLMODE": "disable", "RABBITMQ_HOST": rabbit.Host, "RABBITMQ_PORT": strconv.Itoa(rabbit.Port), "RABBITMQ_USER": rabbit.Username, "RABBITMQ_PASSWORD": rabbit.Password, "RABBITMQ_VHOST": rabbit.Vhost}
}

type e2eOutput struct {
	sync.Mutex
	bytes.Buffer
}

func (o *e2eOutput) Write(data []byte) (int, error) {
	o.Lock()
	defer o.Unlock()
	return o.Buffer.Write(data)
}

// bytes.Buffer's promoted ReadFrom bypasses Write when os/exec uses io.Copy.
// Hide that fast path so concurrent diagnostic snapshots use the same lock.
func (o *e2eOutput) ReadFrom(reader io.Reader) (int64, error) {
	return io.Copy(struct{ io.Writer }{o}, reader)
}

func (o *e2eOutput) String() string { o.Lock(); defer o.Unlock(); return o.Buffer.String() }

type e2eProcess struct {
	cmd    *exec.Cmd
	output e2eOutput
	done   chan struct{}
	err    error
}

func startE2EProcess(t *testing.T, ctx context.Context, binary string, args []string, overrides map[string]string) *e2eProcess {
	t.Helper()
	absolute, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	process := &e2eProcess{done: make(chan struct{})}
	process.cmd = exec.CommandContext(ctx, absolute, args...)
	process.cmd.Env = os.Environ()
	for name, value := range overrides {
		process.cmd.Env = append(process.cmd.Env, name+"="+value)
	}
	process.cmd.Stdout, process.cmd.Stderr = &process.output, &process.output
	if err = process.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { process.err = process.cmd.Wait(); close(process.done) }()
	t.Cleanup(func() { process.stop(t) })
	return process
}
func (p *e2eProcess) waitSuccess(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-p.done:
		if p.err != nil {
			t.Fatalf("process failed: %v\n%s", p.err, p.output.String())
		}
	case <-time.After(timeout):
		t.Fatalf("process did not finish\n%s", p.output.String())
	}
}
func (p *e2eProcess) stop(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		return
	default:
	}
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("interrupt test process: %v", err)
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("kill test process: %v", err)
		}
		<-p.done
	}
}
func awaitE2E(t *testing.T, ctx context.Context, process *e2eProcess, ready func() bool, description string) {
	t.Helper()
	var done <-chan struct{}
	if process != nil {
		done = process.done
	}
	diagnostics := func() string {
		if process == nil {
			return ""
		}
		return process.output.String()
	}
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-done:
			t.Fatalf("%s exited: %v\n%s", description, process.err, process.output.String())
		case <-ctx.Done():
			t.Fatalf("%s context expired\n%s", description, diagnostics())
		case <-deadline.C:
			t.Fatalf("%s readiness timed out\n%s", description, diagnostics())
		case <-ticker.C:
		}
	}
}

// Exclusive auto-delete queues can outlive the process's socket close briefly.
// Probe only with the passive method: a missing queue is never recreated here.
func waitE2EProviderQueuesReleased(t *testing.T, parent context.Context, address, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	connection, err := amqp.DialConfig(address, amqp.Config{Dial: func(network, endpoint string) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, network, endpoint)
		if err != nil {
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			if err := raw.SetDeadline(deadline); err != nil {
				_ = raw.Close()
				return nil, err
			}
		}
		return raw, nil
	}})
	if err != nil {
		t.Fatalf("connect for provider queue release probes: %v", err)
	}
	defer func() {
		if err := connection.CloseDeadline(time.Now().Add(time.Second)); err != nil && !errors.Is(err, amqp.ErrClosed) {
			t.Errorf("close provider release probe: %v", err)
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = connection.CloseDeadline(time.Now()) })
	defer stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	queues := []struct {
		name    string
		durable bool
	}{
		{name + "_crypto_provider_rpc", true},
		{name + "_consuming_container_rpc_resync", true},
		{name + "_container_on_start", false},
	}
	for {
		allReleased := true
		for _, queue := range queues {
			channel, err := connection.Channel()
			if err != nil {
				t.Fatalf("open provider release probe channel: %v", err)
			}
			_, probeErr := channel.QueueDeclarePassive(queue.name, queue.durable, true, false, false, nil)
			if err := channel.Close(); err != nil && !errors.Is(err, amqp.ErrClosed) {
				t.Fatalf("close provider release probe channel: %v", err)
			}
			if probeErr == nil {
				allReleased = false
				continue
			}
			var brokerError *amqp.Error
			if errors.As(probeErr, &brokerError) {
				if brokerError.Code == amqp.NotFound {
					continue
				}
				if brokerError.Code == amqp.ResourceLocked {
					allReleased = false
					continue
				}
			}
			t.Fatalf("passive provider release probe for %s: %v", queue.name, probeErr)
		}
		if allReleased {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("provider's prior exclusive queues were not released before restart")
		case <-ticker.C:
		}
	}
}
