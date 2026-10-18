package main_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// The runner compiles this test alongside the provider's real Mythic lifecycle
// helpers in a private copy of Mythic. Every server and agent is its production
// executable; only C2 metadata and a network-fault forwarding proxy are fixtures.
func TestPoseidonBeaconcryptMythicE2E(t *testing.T) {
	serverBinary := requiredE2EEnv(t, "MYTHIC_TEST_SERVER_BINARY")
	providerBinary := requiredE2EEnv(t, "BEACONCRYPT_TEST_PROVIDER_BINARY")
	containerBinary := requiredE2EEnv(t, "POSEIDON_TEST_CONTAINER_BINARY")
	moduleRoot := requiredE2EEnv(t, "POSEIDON_TEST_MODULE_ROOT")
	brokerURL := requiredE2EEnv(t, "BEACONCRYPT_AMQP_TEST_URL")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	adminDSN := requiredE2EEnv(t, "CRYPTO_PROVIDER_TEST_DSN")
	parsedDSN, err := url.Parse(adminDSN)
	if err != nil || parsedDSN.Scheme != "postgres" && parsedDSN.Scheme != "postgresql" {
		t.Fatal("integration requires a PostgreSQL URL DSN")
	}
	for key := range parsedDSN.Query() {
		if key != "sslmode" && key != "connect_timeout" {
			t.Fatalf("test database DSN query override %q is unsupported", key)
		}
	}
	dsn := isolatedE2EDatabase(t, adminDSN)
	httpPort, grpcPort := freeE2EPort(t), freeE2EPort(t)
	providerName := "poseidon-e2e-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	env := e2eServerEnvironment(t, dsn, brokerURL)
	env["MYTHIC_SERVER_PORT"], env["MYTHIC_SERVER_GRPC_PORT"] = strconv.Itoa(httpPort), strconv.Itoa(grpcPort)
	env["MYTHIC_SERVER_BIND_LOCALHOST_ONLY"], env["MYTHIC_DOCKER_NETWORKING"] = "true", "host"
	env["MYTHIC_SERVER_DYNAMIC_PORTS"], env["CUSTOM_RPC_TIMEOUT"] = "0", "1"
	env["MYTHIC_ADMIN_USER"], env["MYTHIC_ADMIN_PASSWORD"] = "poseidon_e2e_admin", "isolated-integration-password"
	env["DEFAULT_OPERATION_NAME"], env["JWT_SECRET"] = "Poseidon integration", strings.Repeat("p", 48)
	env["DEBUG_LEVEL"], env["MYTHIC_DEBUG_AGENT_MESSAGE"] = "warning", "false"
	env["MYTHIC_SERVER_ALLOW_WEBHOOKS_ON_NEW_CALLBACKS"] = "false"
	server := startE2EProcess(t, ctx, serverBinary, nil, env)
	client := &http.Client{Timeout: 15 * time.Second}
	endpoint := "http://127.0.0.1:" + strconv.Itoa(httpPort)
	awaitE2E(t, ctx, server, func() bool {
		response, requestErr := client.Get(endpoint + "/health")
		if requestErr != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	}, "real Mythic startup")
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedPoseidonHTTPProfile(t, db)
	providerEnv := map[string]string{"RABBITMQ_URL": brokerURL, "BEACONCRYPT_PROVIDER_NAME": providerName, "BEACONCRYPT_NAMESPACE": "poseidon-e2e", "BEACONCRYPT_STATE_ID": "server", "BEACONCRYPT_RPC_TIMEOUT": "20s", "DEBUG_LEVEL": "warning"}
	provider := startE2EProcess(t, ctx, providerBinary, nil, providerEnv)
	waitE2EProviderReady(t, ctx, brokerURL, provider, providerName)
	containerEnv := e2eServerEnvironment(t, dsn, brokerURL)
	containerEnv["MYTHIC_SERVER_HOST"], containerEnv["MYTHIC_SERVER_PORT"], containerEnv["MYTHIC_SERVER_GRPC_PORT"] = "127.0.0.1", strconv.Itoa(httpPort), strconv.Itoa(grpcPort)
	containerEnv["DEBUG_LEVEL"] = "warning"
	// Registered before the container cleanup so its build processes stop before
	// removing this test's one artifact. Other files in /build are untouched.
	var buildArtifact string
	t.Cleanup(func() {
		if buildArtifact != "" {
			if err := os.Remove(buildArtifact); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove test payload artifact: %v", err)
			}
		}
	})
	container := startPoseidonProcess(t, ctx, containerBinary, moduleRoot, containerEnv)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Mythic output:\n%s\nProvider output:\n%s\nPoseidon container output:\n%s", server.output.String(), provider.output.String(), container.output.String())
		}
	})
	awaitE2E(t, ctx, container, func() bool {
		var commands, parameters, steps int
		var supportsBeaconcrypt bool
		if err := db.Get(&supportsBeaconcrypt, `SELECT supported_crypto_schemes ? 'beaconcrypt' FROM payloadtype WHERE name='poseidon' AND container_running AND NOT deleted`); err != nil || !supportsBeaconcrypt {
			return false
		}
		if err := db.Get(&commands, `SELECT count(*) FROM command JOIN payloadtype ON payloadtype.id=command.payload_type_id WHERE payloadtype.name='poseidon' AND payloadtype.container_running AND command.cmd IN ('pwd','exit') AND NOT command.deleted`); err != nil || commands != 2 {
			return false
		}
		if err := db.Get(&parameters, `SELECT count(*) FROM buildparameter JOIN payloadtype ON payloadtype.id=buildparameter.payload_type_id WHERE payloadtype.name='poseidon' AND NOT buildparameter.deleted AND buildparameter.name IN ('mode','architecture','proxy_bypass','garble','debug','egress_order','egress_failover','failover_threshold','static')`); err != nil || parameters != 9 {
			return false
		}
		return db.Get(&steps, `SELECT count(*) FROM payload_build_step JOIN payloadtype ON payloadtype.id=payload_build_step.payloadtype_id WHERE payloadtype.name='poseidon' AND payload_build_step.payload_id IS NULL`) == nil && steps == 3
	}, "actual Poseidon SDK definition sync")
	t.Log("Real Mythic, provider, and Poseidon SDK container are ready")
	login := postPoseidonAPI(t, ctx, client, endpoint+"/auth", "", map[string]string{"username": env["MYTHIC_ADMIN_USER"], "password": env["MYTHIC_ADMIN_PASSWORD"]})
	token, ok := login["access_token"].(string)
	if !ok || token == "" {
		t.Fatalf("real operator login failed: %+v", login)
	}
	proxy := newPoseidonFaultProxy(t, endpoint)
	proxyURL, err := url.Parse(proxy.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyPort, err := strconv.Atoi(proxyURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	configuration := map[string]interface{}{
		"payload_type": "poseidon", "selected_os": "Linux", "filename": "poseidon-beaconcrypt-e2e", "description": "Isolated real Beaconcrypt integration", "commands": []string{"pwd", "exit"},
		"build_parameters": []map[string]interface{}{{"name": "architecture", "value": "AMD_x64"}, {"name": "mode", "value": "default"}, {"name": "garble", "value": false}, {"name": "debug", "value": false}, {"name": "static", "value": false}, {"name": "proxy_bypass", "value": true}, {"name": "egress_order", "value": []string{"http"}}, {"name": "egress_failover", "value": "failover"}, {"name": "failover_threshold", "value": 10}},
		"c2_profiles":      []map[string]interface{}{{"c2_profile": "http", "c2_profile_parameters": map[string]interface{}{"callback_host": "http://127.0.0.1", "callback_port": proxyPort, "callback_interval": 1, "callback_jitter": 0, "killdate": time.Now().AddDate(0, 0, 2).Format("2006-01-02"), "post_uri": "agent_message", "headers": map[string]string{"mythic": "http"}, "encrypted_exchange_check": false, "AESPSK": "provider:" + providerName + ":beaconcrypt"}}},
	}
	configurationBytes, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	build := postPoseidonAPI(t, ctx, client, endpoint+"/createpayload_webhook", token, map[string]interface{}{"input": map[string]string{"payloadDefinition": string(configurationBytes)}})
	payloadUUID, ok := build["uuid"].(string)
	if build["status"] != "success" || !ok {
		t.Fatalf("actual Mythic payload creation failed: %+v", build)
	}
	parsedPayloadUUID, err := uuid.Parse(payloadUUID)
	if err != nil || parsedPayloadUUID.String() != payloadUUID {
		t.Fatalf("actual Mythic payload creation returned an invalid UUID: %q", payloadUUID)
	}
	buildArtifact = filepath.Join("/build", payloadUUID+"-linux-amd64")
	t.Logf("Real Mythic accepted payload build %s", payloadUUID)
	var payloadID int
	var payloadPath string
	awaitPoseidonBuild(t, ctx, db, container, payloadUUID, &payloadID, &payloadPath)
	artifact, err := os.ReadFile(payloadPath)
	if err != nil || len(artifact) < 4 || string(artifact[:4]) != "\x7fELF" {
		t.Fatalf("actual SDK did not upload its built ELF: %v", err)
	}
	t.Logf("Real Poseidon builder uploaded %d-byte ELF", len(artifact))
	agentDirectory := t.TempDir()
	agentPath := filepath.Join(agentDirectory, "poseidon")
	if err = os.WriteFile(agentPath, artifact, 0700); err != nil {
		t.Fatal(err)
	}
	suiteT := t
	if !t.Run("lost_reply_and_provider_restart", func(t *testing.T) {
		agent := startPoseidonProcess(t, ctx, agentPath, agentDirectory, nil)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("Poseidon agent output:\n%s", agent.output.String())
			}
		})
		var callbackID, callbackDisplayID int
		var callbackUUID string
		awaitE2E(t, ctx, agent, func() bool {
			return db.QueryRow(`SELECT id,display_id,agent_callback_id FROM callback WHERE registered_payload_id=$1`, payloadID).Scan(&callbackID, &callbackDisplayID, &callbackUUID) == nil
		}, "actual Poseidon native registration and encrypted check-in")
		t.Logf("Built Poseidon checked in as callback %s", callbackUUID)
		var bindings int
		if err = db.Get(&bindings, `SELECT count(*) FROM callback JOIN crypto_provider_binding b ON callback.crypto_provider_binding_id=b.id WHERE callback.id=$1 AND b.session_ref<>''`, callbackID); err != nil || bindings != 1 {
			t.Fatalf("real callback lacks its durable provider session: %v", err)
		}

		// Hold the next real poll before task submission, then lose its task reply.
		// This ensures the loss occurs after Mythic actually issues the pwd task.
		paused, release := proxy.pause(callbackUUID, true)
		t.Cleanup(release)
		awaitPoseidonSignal(t, ctx, agent, paused, "agent poll paused before task delivery")
		firstTask := createPoseidonTask(t, ctx, client, endpoint, token, callbackDisplayID, "pwd")
		awaitPoseidonTaskSubmitted(t, ctx, db, container, firstTask)
		release()
		awaitPoseidonSignal(t, ctx, agent, proxy.retried, "byte-identical request and committed reply after simulated loss")
		assertPoseidonPWD(t, ctx, db, agent, firstTask, agentDirectory)
		proxy.assertReplay(t)
		t.Log("Real task delivery survived a lost reply with exact ciphertext replay and one pwd response")

		// Retain the same live native agent while the provider restores its ratchets.
		paused, release = proxy.pause(callbackUUID, false)
		t.Cleanup(release)
		awaitPoseidonSignal(t, ctx, agent, paused, "agent poll paused during provider restart")
		provider.stop(t)
		waitE2EProviderQueuesReleased(t, ctx, brokerURL, providerName)
		// This restored provider is shared by later matrix cases. Its cleanup
		// belongs to the suite rather than this recovery subtest.
		provider = startE2EProcess(suiteT, ctx, providerBinary, nil, providerEnv)
		waitE2EProviderReady(t, ctx, brokerURL, provider, providerName)
		secondTask := createPoseidonTask(t, ctx, client, endpoint, token, callbackDisplayID, "pwd")
		awaitPoseidonTaskSubmitted(t, ctx, db, container, secondTask)
		release()
		assertPoseidonPWD(t, ctx, db, agent, secondTask, agentDirectory)
		assertE2EStore(t, db, providerName, 2)
		t.Log("Same live Poseidon completed another pwd after provider restart")
		_ = createPoseidonTask(t, ctx, client, endpoint, token, callbackDisplayID, "exit")
		agent.waitSuccess(t, 30*time.Second)
	}) {
		return
	}
	select {
	case <-provider.done:
		t.Fatalf("shared provider exited before the message matrix: %v\n%s", provider.err, provider.output.String())
	default:
	}
	if !testPoseidonMessageMatrix(t, ctx, db, client, endpoint, token, agentPath, payloadID, container, proxy) {
		return
	}
	assertPoseidonMatrixTotals(t, db, payloadID, providerName)
	provider.stop(t)
	container.stop(t)
}

// One matrix message is one operator-created pwd task and its authenticated
// response. Registration, check-in, idle polls, and exit control tasks are extra
// protocol traffic; they are not counted as the requested one to three messages.
func testPoseidonMessageMatrix(t *testing.T, ctx context.Context, db *sqlx.DB, client *http.Client, endpoint, token, binary string, payloadID int, container *e2eProcess, proxy *poseidonFaultProxy) bool {
	t.Helper()
	for agentCount := 1; agentCount <= 3; agentCount++ {
		for messageCount := 1; messageCount <= 3; messageCount++ {
			if !t.Run(fmt.Sprintf("agents_%d/messages_%d", agentCount, messageCount), func(t *testing.T) {
				agents := make([]poseidonMatrixAgent, agentCount)
				// Start every real ELF before waiting for any callback. Each process
				// generates its own native identity and has an unmistakable pwd.
				for i := range agents {
					agent := &agents[i]
					agent.directory = t.TempDir()
					agent.process = startPoseidonProcess(t, ctx, binary, agent.directory, nil)
					t.Cleanup(func() {
						if t.Failed() {
							t.Logf("Matrix Poseidon PID %d output:\n%s", agent.process.cmd.Process.Pid, agent.process.output.String())
						}
					})
				}
				callbacks := make([]string, len(agents))
				for i := range agents {
					agent := &agents[i]
					awaitPoseidonMatrixCallback(t, ctx, db, payloadID, agent)
					callbacks[i] = agent.callbackUUID
				}
				for round := 0; round < messageCount; round++ {
					barrier := proxy.pauseTogether(t, callbacks)
					t.Cleanup(barrier.release)
					awaitPoseidonSignal(t, ctx, agents[0].process, barrier.arrived, "all real agent polls held concurrently")
					for i := range agents {
						select {
						case <-agents[i].process.done:
							t.Fatalf("matrix agent %d exited while all peer polls were held", i)
						default:
						}
						agents[i].tasks = append(agents[i].tasks, createPoseidonTask(t, ctx, client, endpoint, token, agents[i].callbackDisplayID, "pwd"))
					}
					for i := range agents {
						awaitPoseidonTaskSubmitted(t, ctx, db, container, agents[i].tasks[round])
					}
					// One release forwards the actual polls together. The proxy also
					// holds their real Mythic replies until every peer has a reply.
					barrier.release()
					awaitPoseidonSignal(t, ctx, agents[0].process, barrier.replied, "real Mythic replied to every simultaneous agent poll")
					for i := range agents {
						assertPoseidonPWD(t, ctx, db, agents[i].process, agents[i].tasks[round], agents[i].directory)
					}
					barrier.assertComplete(t, agentCount)
				}
				// Submit all exit controls before waiting for any child to exit.
				for i := range agents {
					_ = createPoseidonTask(t, ctx, client, endpoint, token, agents[i].callbackDisplayID, "exit")
				}
				for i := range agents {
					agent := &agents[i]
					agent.process.waitSuccess(t, 30*time.Second)
					var tasks, responses, pwdTasks, exitTasks int
					if err := db.QueryRow(`SELECT count(*),count(*) FILTER (WHERE command_name='pwd'),count(*) FILTER (WHERE command_name='exit') FROM task WHERE callback_id=$1`, agent.callbackID).Scan(&tasks, &pwdTasks, &exitTasks); err != nil || tasks != messageCount+1 || pwdTasks != messageCount || exitTasks != 1 {
						t.Fatalf("matrix callback %s task count: total=%d pwd=%d exit=%d error=%v", agent.callbackUUID, tasks, pwdTasks, exitTasks, err)
					}
					if err := db.Get(&responses, `SELECT count(*) FROM response JOIN task ON task.id=response.task_id WHERE task.callback_id=$1`, agent.callbackID); err != nil || responses != messageCount {
						t.Fatalf("matrix callback %s has unexpected responses after exit: got=%d want=%d error=%v", agent.callbackUUID, responses, messageCount, err)
					}
					// Recheck after process exit so a delayed duplicate or cross-agent
					// response cannot pass a transient completion check.
					for _, task := range agent.tasks {
						assertPoseidonPWD(t, ctx, db, agent.process, task, agent.directory)
					}
				}
				t.Logf("Completed %d real agents × %d messages with simultaneous polls and isolated sessions", agentCount, messageCount)
			}) {
				return false
			}
		}
	}
	return true
}

type poseidonMatrixAgent struct {
	process                       *e2eProcess
	directory, callbackUUID       string
	callbackID, callbackDisplayID int
	tasks                         []int
}

func awaitPoseidonMatrixCallback(t *testing.T, ctx context.Context, db *sqlx.DB, payloadID int, agent *poseidonMatrixAgent) {
	t.Helper()
	var cwd string
	awaitE2E(t, ctx, agent.process, func() bool {
		return db.QueryRow(`SELECT id,display_id,agent_callback_id,cwd FROM callback WHERE registered_payload_id=$1 AND pid=$2`, payloadID, agent.process.cmd.Process.Pid).Scan(&agent.callbackID, &agent.callbackDisplayID, &agent.callbackUUID, &cwd) == nil
	}, "real matrix Poseidon registered its process and checked in")
	if cwd != agent.directory {
		t.Fatalf("callback %s check-in directory=%q want=%q", agent.callbackUUID, cwd, agent.directory)
	}
	var callbacks, routes, bindings, sessions, nativeIdentities int
	if err := db.QueryRow(`SELECT count(*),count(DISTINCT callback.agent_callback_id),count(DISTINCT b.id),count(DISTINCT b.session_ref),count(DISTINCT s.provider_json #>> ARRAY['sessions',b.session_ref,'key_id'])
		FROM callback JOIN crypto_provider_binding b ON b.id=callback.crypto_provider_binding_id
		JOIN crypto_provider_state s ON s.provider_id=b.provider_id AND s.namespace=b.namespace AND s.state_id=b.state_id
		WHERE callback.registered_payload_id=$1`, payloadID).Scan(&callbacks, &routes, &bindings, &sessions, &nativeIdentities); err != nil || callbacks != routes || callbacks != bindings || callbacks != sessions || callbacks != nativeIdentities {
		t.Fatalf("real agents must have distinct callback/session/native identities: callbacks=%d routes=%d bindings=%d sessions=%d native=%d error=%v", callbacks, routes, bindings, sessions, nativeIdentities, err)
	}
	var binding, session, keyID string
	if err := db.QueryRow(`SELECT b.id::text,b.session_ref,s.provider_json #>> ARRAY['sessions',b.session_ref,'key_id'] FROM callback JOIN crypto_provider_binding b ON b.id=callback.crypto_provider_binding_id JOIN crypto_provider_state s ON s.provider_id=b.provider_id AND s.namespace=b.namespace AND s.state_id=b.state_id WHERE callback.id=$1`, agent.callbackID).Scan(&binding, &session, &keyID); err != nil || binding == "" || session == "" || keyID == "" || keyID == "18446744073709551615" {
		t.Fatalf("real matrix callback has no committed native session: binding=%q session=%q key_id=%q error=%v", binding, session, keyID, err)
	}
}

func assertPoseidonMatrixTotals(t *testing.T, db *sqlx.DB, payloadID int, providerName string) {
	t.Helper()
	var callbacks, tasks, messages, responses int
	if err := db.Get(&callbacks, `SELECT count(*) FROM callback WHERE registered_payload_id=$1`, payloadID); err != nil || callbacks != 19 {
		t.Fatalf("matrix plus recovery must create 19 real callbacks: got=%d error=%v", callbacks, err)
	}
	if err := db.QueryRow(`SELECT count(*),count(*) FILTER (WHERE task.command_name='pwd') FROM task JOIN callback ON callback.id=task.callback_id WHERE callback.registered_payload_id=$1`, payloadID).Scan(&tasks, &messages); err != nil || tasks != 57 || messages != 38 {
		t.Fatalf("matrix expected 36 message exchanges plus recovery's 2 and 19 exit controls: tasks=%d messages=%d error=%v", tasks, messages, err)
	}
	if err := db.Get(&responses, `SELECT count(*) FROM response JOIN task ON task.id=response.task_id JOIN callback ON callback.id=task.callback_id WHERE callback.registered_payload_id=$1`, payloadID); err != nil || responses != 38 {
		t.Fatalf("matrix plus recovery must store exactly 38 responses: got=%d error=%v", responses, err)
	}
	assertE2EStore(t, db, providerName, 2)
}

func seedPoseidonHTTPProfile(t *testing.T, db *sqlx.DB) {
	t.Helper()
	var c2ID int
	if err := db.QueryRow(`INSERT INTO c2profile(name,is_p2p,container_running,running) VALUES('http',false,true,true) RETURNING id`).Scan(&c2ID); err != nil {
		t.Fatal(err)
	}
	parameters := []struct{ name, kind, defaultValue string }{{"AESPSK", "ChooseOne", "none"}, {"callback_host", "String", "http://127.0.0.1"}, {"callback_port", "Number", "80"}, {"callback_interval", "Number", "1"}, {"callback_jitter", "Number", "0"}, {"killdate", "Date", "2"}, {"post_uri", "String", "agent_message"}, {"headers", "Dictionary", "{}"}, {"encrypted_exchange_check", "Boolean", "false"}}
	for _, p := range parameters {
		if _, err := db.Exec(`INSERT INTO c2profileparameters(c2_profile_id,description,name,parameter_type,default_value,crypto_type) VALUES($1,'Poseidon integration',$2,$3,$4,$5)`, c2ID, p.name, p.kind, p.defaultValue, p.name == "AESPSK"); err != nil {
			t.Fatal(err)
		}
	}
}

func postPoseidonAPI(t *testing.T, ctx context.Context, client *http.Client, address, token string, body interface{}) map[string]interface{} {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]interface{}
	if err = json.NewDecoder(response.Body).Decode(&result); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("actual Mythic operator API %s: HTTP %d, %v, %+v", address, response.StatusCode, err, result)
	}
	return result
}

func createPoseidonTask(t *testing.T, ctx context.Context, client *http.Client, endpoint, token string, callback int, command string) int {
	t.Helper()
	response := postPoseidonAPI(t, ctx, client, endpoint+"/create_task_webhook", token, map[string]interface{}{"input": map[string]interface{}{"callback_display_id": callback, "command": command, "params": ""}})
	id, ok := response["id"].(float64)
	if response["status"] != "success" || !ok {
		t.Fatalf("actual %s task creation failed: %+v", command, response)
	}
	return int(id)
}

func awaitPoseidonBuild(t *testing.T, ctx context.Context, db *sqlx.DB, container *e2eProcess, payload string, id *int, path *string) {
	t.Helper()
	deadline, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for {
		var phase, message, stderr string
		err := db.QueryRow(`SELECT payload.id,payload.build_phase,payload.build_message,payload.build_stderr,filemeta.path FROM payload JOIN filemeta ON payload.file_id=filemeta.id WHERE payload.uuid=$1`, payload).Scan(id, &phase, &message, &stderr, path)
		if err == nil && phase == "success" {
			return
		}
		if err == nil && phase == "error" {
			t.Fatalf("real Poseidon build failed: %s\n%s\n%s", message, stderr, container.output.String())
		}
		select {
		case <-deadline.Done():
			t.Fatalf("real Poseidon build timeout: phase=%s error=%v\n%s\n%s\n%s", phase, err, message, stderr, container.output.String())
		case <-container.done:
			t.Fatalf("Poseidon container exited: %v\n%s", container.err, container.output.String())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func awaitPoseidonTaskSubmitted(t *testing.T, ctx context.Context, db *sqlx.DB, container *e2eProcess, id int) {
	t.Helper()
	awaitE2E(t, ctx, container, func() bool {
		var status string
		return db.Get(&status, `SELECT status FROM task WHERE id=$1`, id) == nil && status == "submitted"
	}, "real Poseidon task callbacks submitted command")
}

func assertPoseidonPWD(t *testing.T, ctx context.Context, db *sqlx.DB, agent *e2eProcess, id int, expected string) {
	t.Helper()
	awaitE2E(t, ctx, agent, func() bool {
		var completed bool
		// Mythic marks completion and persists asynchronous responses separately.
		// Observe both commits before asserting the exact stored response below.
		return db.Get(&completed, `SELECT completed AND EXISTS(SELECT 1 FROM response WHERE task_id=task.id) FROM task WHERE id=$1`, id) == nil && completed
	}, "real Poseidon executed and posted pwd response")
	var responses [][]byte
	if err := db.Select(&responses, `SELECT response FROM response WHERE task_id=$1 ORDER BY id`, id); err != nil || len(responses) != 1 || string(responses[0]) != expected {
		t.Fatalf("pwd output must be stored exactly once: count=%d output=%q error=%v", len(responses), responses, err)
	}
}

func startPoseidonProcess(t *testing.T, ctx context.Context, binary, directory string, env map[string]string) *e2eProcess {
	t.Helper()
	process := &e2eProcess{done: make(chan struct{})}
	process.cmd = exec.CommandContext(ctx, binary)
	process.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	process.cmd.Cancel = func() error {
		err := syscall.Kill(-process.cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	process.cmd.WaitDelay = 5 * time.Second
	process.cmd.Dir, process.cmd.Env = directory, os.Environ()
	for name, value := range env {
		process.cmd.Env = append(process.cmd.Env, name+"="+value)
	}
	process.cmd.Stdout, process.cmd.Stderr = &process.output, &process.output
	if err := process.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { process.err = process.cmd.Wait(); close(process.done) }()
	t.Cleanup(func() {
		process.stop(t)
		if err := syscall.Kill(-process.cmd.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			t.Errorf("kill Poseidon build process group: %v", err)
		}
	})
	return process
}

func awaitPoseidonSignal(t *testing.T, ctx context.Context, agent *e2eProcess, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-agent.done:
		t.Fatalf("%s: agent exited %v\n%s", description, agent.err, agent.output.String())
	case <-ctx.Done():
		t.Fatalf("%s: context expired", description)
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: timeout\n%s", description, agent.output.String())
	}
}

type poseidonFaultProxy struct {
	mu                       sync.Mutex
	server                   *httptest.Server
	transport                *http.Transport
	callback                 string
	paused, release, retried chan struct{}
	pauseNext, drop, dropped bool
	replayed                 bool
	request, response        []byte
	err                      error
	barriers                 map[string]*poseidonPollBarrier
}

// Every participant is a real HTTP request from a different live agent. Requests
// wait together before forwarding, and their actual Mythic replies wait together
// before delivery. The proxy never fabricates a protocol response.
type poseidonPollBarrier struct {
	mu                     sync.Mutex
	expected, arrivals     int
	replies                int
	arrived, proceed       chan struct{}
	replied, aborted       chan struct{}
	releaseOnce, abortOnce sync.Once
}

func (b *poseidonPollBarrier) release() { b.releaseOnce.Do(func() { close(b.proceed) }) }

func (b *poseidonPollBarrier) abort() {
	b.release()
	b.abortOnce.Do(func() { close(b.aborted) })
}

func (b *poseidonPollBarrier) awaitForward(ctx context.Context) bool {
	b.mu.Lock()
	b.arrivals++
	if b.arrivals == b.expected {
		close(b.arrived)
	}
	b.mu.Unlock()
	select {
	case <-b.proceed:
		return true
	case <-b.aborted:
	case <-ctx.Done():
	}
	return false
}

func (b *poseidonPollBarrier) awaitReply(ctx context.Context) bool {
	b.mu.Lock()
	b.replies++
	if b.replies == b.expected {
		close(b.replied)
	}
	b.mu.Unlock()
	select {
	case <-b.replied:
		return true
	case <-b.aborted:
	case <-ctx.Done():
	}
	return false
}

func (b *poseidonPollBarrier) assertComplete(t *testing.T, expected int) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.expected != expected || b.arrivals != expected || b.replies != expected {
		t.Fatalf("concurrent real-agent exchange incomplete: expected=%d arrivals=%d real replies=%d", expected, b.arrivals, b.replies)
	}
}

func newPoseidonFaultProxy(t *testing.T, upstream string) *poseidonFaultProxy {
	t.Helper()
	p := &poseidonFaultProxy{transport: &http.Transport{Proxy: nil}, retried: make(chan struct{}), barriers: make(map[string]*poseidonPollBarrier)}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw, _ := base64.StdEncoding.DecodeString(string(request))
		p.mu.Lock()
		var barrier *poseidonPollBarrier
		if len(raw) >= 36 {
			callback := string(raw[:36])
			barrier = p.barriers[callback]
			delete(p.barriers, callback)
		}
		if barrier != nil {
			p.mu.Unlock()
			if !barrier.awaitForward(r.Context()) {
				return
			}
			p.mu.Lock()
		}
		isCallback := len(raw) >= 36 && string(raw[:36]) == p.callback
		if isCallback && p.pauseNext {
			p.pauseNext = false
			close(p.paused)
			release := p.release
			p.mu.Unlock()
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			p.mu.Lock()
		}
		isRetry := isCallback && p.dropped && !p.replayed
		if isRetry && !bytes.Equal(request, p.request) {
			p.err = fmt.Errorf("agent retry changed ciphertext after lost reply")
		}
		p.mu.Unlock()
		forward, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream+r.URL.RequestURI(), bytes.NewReader(request))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		forward.Header = r.Header.Clone()
		response, err := p.transport.RoundTrip(forward)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if barrier != nil && !barrier.awaitReply(r.Context()) {
			return
		}
		p.mu.Lock()
		if isCallback && p.drop && !p.dropped && response.StatusCode == http.StatusOK {
			p.dropped, p.request, p.response = true, bytes.Clone(request), bytes.Clone(body)
			p.mu.Unlock()
			// No HTTP headers reach the agent; the server has already committed.
			connection, _, hijackErr := w.(http.Hijacker).Hijack()
			if hijackErr == nil {
				_ = connection.Close()
			}
			return
		}
		if isRetry && !p.replayed {
			if response.StatusCode != http.StatusOK || !bytes.Equal(body, p.response) {
				p.err = fmt.Errorf("real Mythic retry changed committed reply: HTTP %d", response.StatusCode)
			}
			p.replayed = true
			close(p.retried)
		}
		p.mu.Unlock()
		for name, values := range response.Header {
			w.Header()[name] = values
		}
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(body)
	}))
	t.Cleanup(func() { p.server.CloseClientConnections(); p.server.Close(); p.transport.CloseIdleConnections() })
	return p
}

func (p *poseidonFaultProxy) pauseTogether(t *testing.T, callbacks []string) *poseidonPollBarrier {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	b := &poseidonPollBarrier{expected: len(callbacks), arrived: make(chan struct{}), proceed: make(chan struct{}), replied: make(chan struct{}), aborted: make(chan struct{})}
	for _, callback := range callbacks {
		if callback == "" || p.barriers[callback] != nil {
			t.Fatalf("duplicate or empty simultaneous-poll callback %q", callback)
		}
		p.barriers[callback] = b
	}
	t.Cleanup(func() {
		b.abort()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, callback := range callbacks {
			if p.barriers[callback] == b {
				delete(p.barriers, callback)
			}
		}
	})
	return b
}

func (p *poseidonFaultProxy) pause(callback string, drop bool) (<-chan struct{}, func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.callback, p.pauseNext, p.drop = callback, true, drop
	p.paused, p.release = make(chan struct{}), make(chan struct{})
	release := p.release
	var once sync.Once
	return p.paused, func() { once.Do(func() { close(release) }) }
}

func (p *poseidonFaultProxy) assertReplay(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil || !p.dropped || !p.replayed {
		t.Fatalf("network-loss recovery failed: dropped=%v replayed=%v err=%v", p.dropped, p.replayed, p.err)
	}
}
