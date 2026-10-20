package native

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/engine"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	"github.com/google/uuid"
)

func TestEngineNativeProtocolAndDurableRecovery(t *testing.T) {
	ctx := context.Background()
	store := &integrationStore{results: map[string]wire.OperationResult{}}
	owner := newIntegrationEngine(t, store, true)
	profileRequest := integrationRequest(wire.PrepareProfile)
	profile := owner.Handle(ctx, profileRequest)
	requireIntegrationReply(t, profileRequest, profile)
	var material struct {
		Version         int    `json:"version"`
		ServerKID       string `json:"server_kid"`
		ServerPublicKey []byte `json:"server_public_key"`
	}
	if err := json.Unmarshal(profile.AgentConfig, &material); err != nil || material.Version != 1 {
		t.Fatalf("profile build material: %v", err)
	}
	serverKID, err := strconv.ParseUint(material.ServerKID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	first, firstSession := beginIntegrationSession(t, owner, profile, serverKID, material.ServerPublicKey)
	second, secondSession := beginIntegrationSession(t, owner, profile, serverKID, material.ServerPublicKey)
	message := []byte{0, 255, 128, '\n', '{', '}'}
	ciphertext, err := second.EncryptToServer(message)
	if err != nil {
		t.Fatal(err)
	}
	wrong := integrationSessionRequest(wire.Open, profile, firstSession)
	wrong.Message = ciphertext
	before, err := store.Load(ctx, wire.StateKey{Namespace: profile.Namespace, StateID: profile.StateID})
	if err != nil {
		t.Fatal(err)
	}
	wrongReply := owner.Handle(ctx, wrong)
	if wrongReply.Success || wrongReply.Error == nil || wrongReply.Error.Outcome != wire.OutcomeRejected || len(wrongReply.Message) != 0 {
		t.Fatalf("wrong route did not reject before native work: %+v", wrongReply)
	}
	after, err := store.Load(ctx, before.StateKey)
	if err != nil || !bytes.Equal(before.StateBlob, after.StateBlob) {
		t.Fatalf("wrong route consumed native checkpoint: %v", err)
	}
	correct := integrationSessionRequest(wire.Open, profile, secondSession)
	correct.Message = ciphertext
	opened := owner.Handle(ctx, correct)
	requireIntegrationReply(t, correct, opened)
	if !bytes.Equal(opened.Message, message) {
		t.Fatal("correct route lost original plaintext")
	}

	sealRequest := integrationSessionRequest(wire.Seal, profile, firstSession)
	sealRequest.Message = message
	sealed := owner.Handle(ctx, sealRequest)
	requireIntegrationReply(t, sealRequest, sealed)
	plaintext, err := first.DecryptServerMessage(sealed.Message)
	if err != nil || !bytes.Equal(plaintext, message) {
		t.Fatalf("real client could not decrypt engine reply: %v", err)
	}
	owner.Close()
	restored := newIntegrationEngine(t, store, false)
	sealRequest.AuthContext = "renewed context"
	replayed := restored.Handle(ctx, sealRequest)
	requireIntegrationReply(t, sealRequest, replayed)
	if !bytes.Equal(sealed.Message, replayed.Message) {
		t.Fatal("restart did not preserve exact sealed result")
	}

	valid, err := first.EncryptToServer([]byte("survives invalid ciphertext and native reload"))
	if err != nil {
		t.Fatal(err)
	}
	invalidRequest := integrationSessionRequest(wire.Open, profile, firstSession)
	invalidRequest.Message = corruptFrame(t, valid)
	invalidReply := restored.Handle(ctx, invalidRequest)
	if invalidReply.Success || invalidReply.Error == nil || invalidReply.Error.Outcome != wire.OutcomeRejected {
		t.Fatalf("ordinary native rejection was not safely recoverable: %+v", invalidReply)
	}
	resumeRequest := integrationSessionRequest(wire.Open, profile, firstSession)
	resumeRequest.Message = valid
	resumed := restored.Handle(ctx, resumeRequest)
	requireIntegrationReply(t, resumeRequest, resumed)
	if string(resumed.Message) != "survives invalid ciphertext and native reload" {
		t.Fatal("native reload lost the unconsumed valid packet")
	}
}

func TestEngineNativeCommitFailureDoesNotReleaseOrConsumeClientMessage(t *testing.T) {
	for _, method := range []string{wire.Open, wire.Seal} {
		t.Run(method, func(t *testing.T) {
			owner, store, client, profile, session := nativeIntegrationFixture(t)
			message := []byte("retry the exact operation after storage failure")
			request := integrationSessionRequest(method, profile, session)
			request.Message = message
			if method == wire.Open {
				var err error
				request.Message, err = client.EncryptToServer(message)
				if err != nil {
					t.Fatal(err)
				}
			}
			before := cloneIntegrationState(*store.state)
			store.failCommit = true
			failed := owner.Handle(context.Background(), request)
			if failed.Success || failed.Error == nil || failed.Error.Outcome != wire.OutcomeUnresolved || len(failed.Message) != 0 {
				t.Fatalf("uncommitted native result escaped: %+v", failed)
			}
			if !bytes.Equal(before.StateBlob, store.state.StateBlob) || !bytes.Equal(before.ProviderJSON, store.state.ProviderJSON) || before.Revision != store.state.Revision {
				t.Fatal("failed transaction changed the durable snapshot or metadata")
			}
			if _, ok := store.results[request.RequestID]; ok {
				t.Fatal("failed transaction retained an immutable result")
			}
			retried := owner.Handle(context.Background(), request)
			requireIntegrationReply(t, request, retried)
			if method == wire.Open {
				if !bytes.Equal(retried.Message, message) {
					t.Fatal("accepted receive was lost when its transaction failed")
				}
			} else if opened, err := client.DecryptServerMessage(retried.Message); err != nil || !bytes.Equal(opened, message) {
				t.Fatalf("retried send lost client ratchet continuity: %v", err)
			}
			// A further retry returns the saved bytes, including for a receive
			// whose ciphertext the live native owner has already consumed.
			again := owner.Handle(context.Background(), request)
			requireIntegrationReply(t, request, again)
			if !bytes.Equal(retried.Message, again.Message) {
				t.Fatal("durable retry changed the exact native result")
			}
		})
	}
}

func TestEngineNativeLostCommitAcknowledgementPreservesExactResult(t *testing.T) {
	for _, method := range []string{wire.Open, wire.Seal} {
		t.Run(method, func(t *testing.T) {
			owner, store, client, profile, session := nativeIntegrationFixture(t)
			message := []byte("committed despite a lost acknowledgement")
			request := integrationSessionRequest(method, profile, session)
			request.Message = message
			if method == wire.Open {
				var err error
				request.Message, err = client.EncryptToServer(message)
				if err != nil {
					t.Fatal(err)
				}
			}
			store.loseCommitAck = true
			first := owner.Handle(context.Background(), request)
			requireIntegrationReply(t, request, first)
			if method == wire.Seal {
				opened, err := client.DecryptServerMessage(first.Message)
				if err != nil || !bytes.Equal(opened, message) {
					t.Fatalf("committed reply cannot be consumed by its real client: %v", err)
				}
			} else if !bytes.Equal(first.Message, message) {
				t.Fatal("committed plaintext was not recovered from the result journal")
			}
			owner.Close()
			restored := newIntegrationEngine(t, store, false)
			again := restored.Handle(context.Background(), request)
			requireIntegrationReply(t, request, again)
			if !bytes.Equal(first.Message, again.Message) {
				t.Fatal("restart changed a result whose commit acknowledgement was lost")
			}
			nextMessage := []byte("same live client after ambiguous commit and restart")
			ciphertext, err := client.EncryptToServer(nextMessage)
			if err != nil {
				t.Fatal(err)
			}
			next := integrationSessionRequest(wire.Open, profile, session)
			next.Message = ciphertext
			opened := restored.Handle(context.Background(), next)
			requireIntegrationReply(t, next, opened)
			if !bytes.Equal(opened.Message, nextMessage) {
				t.Fatal("ambiguous commit broke the live client ratchet")
			}
		})
	}
}

func TestEngineNativeCommitFencesReplacedOwnerBeforeResultRelease(t *testing.T) {
	owner, store, client, profile, session := nativeIntegrationFixture(t)
	ciphertext, err := client.EncryptToServer([]byte("only the current owner may release this"))
	if err != nil {
		t.Fatal(err)
	}
	request := integrationSessionRequest(wire.Open, profile, session)
	request.Message = ciphertext
	before := bytes.Clone(store.state.StateBlob)
	store.replaceOwnerBeforeCommit = true
	failed := owner.Handle(context.Background(), request)
	if failed.Success || failed.Error == nil || failed.Error.Outcome != wire.OutcomeUnresolved || len(failed.Message) != 0 {
		t.Fatalf("replaced owner released an uncommitted receive: %+v", failed)
	}
	if !bytes.Equal(before, store.state.StateBlob) {
		t.Fatal("replaced owner overwrote the authoritative snapshot")
	}
	if result := owner.Handle(context.Background(), request); result.Success || len(result.Message) != 0 {
		t.Fatalf("replaced owner was not terminally fenced: %+v", result)
	}
	replacement := newIntegrationEngine(t, store, false)
	opened := replacement.Handle(context.Background(), request)
	requireIntegrationReply(t, request, opened)
	if string(opened.Message) != "only the current owner may release this" {
		t.Fatal("the fenced attempt consumed the current owner's packet")
	}
}

func TestEngineNativeRejectedReceiveDoesNotWriteSnapshotOrJournal(t *testing.T) {
	owner, store, client, profile, session := nativeIntegrationFixture(t)
	ciphertext, err := client.EncryptToServer([]byte("still usable after rejection"))
	if err != nil {
		t.Fatal(err)
	}
	before, commits, results := cloneIntegrationState(*store.state), store.commitCalls, len(store.results)
	invalid := integrationSessionRequest(wire.Open, profile, session)
	invalid.Message = corruptFrame(t, ciphertext)
	failed := owner.Handle(context.Background(), invalid)
	if failed.Success || failed.Error == nil || failed.Error.Outcome != wire.OutcomeRejected || len(failed.Message) != 0 {
		t.Fatalf("invalid receive did not reject cleanly: %+v", failed)
	}
	if store.commitCalls != commits || len(store.results) != results || store.state.Revision != before.Revision || !bytes.Equal(store.state.StateBlob, before.StateBlob) || !bytes.Equal(store.state.ProviderJSON, before.ProviderJSON) {
		t.Fatal("rejected receive wrote the snapshot, metadata, or result journal")
	}
	valid := integrationSessionRequest(wire.Open, profile, session)
	valid.Message = ciphertext
	opened := owner.Handle(context.Background(), valid)
	requireIntegrationReply(t, valid, opened)
	if string(opened.Message) != "still usable after rejection" {
		t.Fatal("rejection consumed the original valid packet")
	}
}

func nativeIntegrationFixture(t *testing.T) (*engine.Engine, *integrationStore, *beaconcrypt.Beacon, wire.Response, wire.Response) {
	t.Helper()
	store := &integrationStore{results: map[string]wire.OperationResult{}}
	owner := newIntegrationEngine(t, store, true)
	request := integrationRequest(wire.PrepareProfile)
	profile := owner.Handle(context.Background(), request)
	requireIntegrationReply(t, request, profile)
	var material struct {
		ServerKID       string `json:"server_kid"`
		ServerPublicKey []byte `json:"server_public_key"`
	}
	if err := json.Unmarshal(profile.AgentConfig, &material); err != nil {
		t.Fatal(err)
	}
	serverKID, err := strconv.ParseUint(material.ServerKID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	client, session := beginIntegrationSession(t, owner, profile, serverKID, material.ServerPublicKey)
	return owner, store, client, profile, session
}

func newIntegrationEngine(t *testing.T, store engine.Store, initialize bool) *engine.Engine {
	t.Helper()
	owner, err := engine.New(engine.Config{Namespace: "native-e2e", StateID: "server", Initialize: initialize}, Factory{}, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	if err := owner.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return owner
}

func integrationRequest(method string) wire.Request {
	return wire.Request{APIVersion: wire.APIVersion, RequestID: uuid.NewString(), OperationScopeID: 9, Method: method, Scheme: engine.Scheme, AuthContext: "test context"}
}

func integrationSessionRequest(method string, profile, session wire.Response) wire.Request {
	request := integrationRequest(method)
	request.ProfileRef, request.SessionRef = profile.ProfileRef, session.SessionRef
	request.Namespace, request.StateID = session.Namespace, session.StateID
	return request
}

func requireIntegrationReply(t *testing.T, request wire.Request, reply wire.Response) {
	t.Helper()
	if err := reply.Validate(request); err != nil || !reply.Success {
		t.Fatalf("%s failed: %v (%+v)", request.Method, err, reply.Error)
	}
}

func beginIntegrationSession(t *testing.T, owner *engine.Engine, profile wire.Response, serverKID uint64, publicKey []byte) (*beaconcrypt.Beacon, wire.Response) {
	t.Helper()
	return beginIntegrationSessionWithScheme(t, owner, profile, serverKID, publicKey, engine.Scheme)
}

func beginIntegrationSessionWithScheme(t *testing.T, owner *engine.Engine, profile wire.Response, serverKID uint64, publicKey []byte, scheme string) (*beaconcrypt.Beacon, wire.Response) {
	t.Helper()
	client, err := beaconcrypt.NewBeacon(serverKID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	registration, err := client.GenerateRegistration()
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.NewString()
	message, err := json.Marshal(map[string]string{"action": "staging", "session_id": sessionID, "data": base64.StdEncoding.EncodeToString(registration)})
	if err != nil {
		t.Fatal(err)
	}
	request := integrationRequest(wire.BeginSession)
	request.Scheme = scheme
	request.ProfileRef, request.PayloadUUID, request.NextUUID, request.Message = profile.ProfileRef, uuid.NewString(), uuid.NewString(), message
	response := owner.Handle(context.Background(), request)
	requireIntegrationReply(t, request, response)
	var outer struct {
		UUID      string `json:"uuid"`
		SessionID string `json:"session_id"`
		Data      []byte `json:"data"`
	}
	if err := json.Unmarshal(response.Message, &outer); err != nil || outer.UUID != request.NextUUID || outer.SessionID != sessionID {
		t.Fatalf("staging wrapper: %v", err)
	}
	initial, err := client.ProcessInitialMessage(outer.Data)
	if err != nil {
		t.Fatal(err)
	}
	var authenticated struct {
		Action    string `json:"action"`
		Status    string `json:"status"`
		UUID      string `json:"uuid"`
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(initial, &authenticated); err != nil || authenticated.Action != "staging" || authenticated.Status != "success" || authenticated.UUID != outer.UUID || authenticated.SessionID != sessionID {
		t.Fatalf("authenticated staging content: %v", err)
	}
	return client, response
}

// This test store provides the same atomic state/result CAS boundary as the
// Mythic service. Native work and protocol composition remain real.
type integrationStore struct {
	mu                                                  sync.Mutex
	state                                               *wire.StoredState
	results                                             map[string]wire.OperationResult
	failCommit, loseCommitAck, replaceOwnerBeforeCommit bool
	commitCalls                                         int
}

func (s *integrationStore) Load(_ context.Context, key wire.StateKey) (wire.StoredState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil || s.state.StateKey != key {
		return wire.StoredState{}, wire.ErrNotFound
	}
	return cloneIntegrationState(*s.state), nil
}

func (s *integrationStore) Create(_ context.Context, req wire.CreateStateRequest) (wire.StoredState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		return wire.StoredState{}, wire.ErrAlreadyExists
	}
	state := wire.StoredState{StateKey: req.StateKey, StateBlob: bytes.Clone(req.StateBlob), ProviderJSON: bytes.Clone(req.ProviderJSON)}
	s.state = &state
	return cloneIntegrationState(state), nil
}

func (s *integrationStore) Acquire(_ context.Context, req wire.AcquireStateRequest) (wire.StoredState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil || s.state.StateKey != req.StateKey {
		return wire.StoredState{}, wire.ErrNotFound
	}
	if s.state.OwnerEpoch != req.ExpectedOwnerEpoch {
		return wire.StoredState{}, wire.ErrStaleWriter
	}
	s.state.OwnerEpoch++
	return cloneIntegrationState(*s.state), nil
}

func (s *integrationStore) Commit(_ context.Context, req wire.CommitStateRequest) (wire.CommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitCalls++
	if s.state == nil || s.state.StateKey != req.StateKey {
		return wire.CommitResult{}, wire.ErrNotFound
	}
	if prior, ok := s.results[req.RequestID]; ok {
		if prior.InputDigest != req.InputDigest {
			return wire.CommitResult{}, wire.ErrRequestConflict
		}
		return wire.CommitResult{Revision: prior.Revision, Result: bytes.Clone(prior.Result), Cached: true}, nil
	}
	if s.replaceOwnerBeforeCommit {
		s.replaceOwnerBeforeCommit = false
		s.state.OwnerEpoch++
	}
	if s.state.Revision != req.ExpectedRevision || s.state.OwnerEpoch != req.OwnerEpoch {
		return wire.CommitResult{}, wire.ErrStaleWriter
	}
	if s.failCommit {
		s.failCommit = false
		return wire.CommitResult{}, errors.New("commit not delivered")
	}
	s.state.Revision++
	s.state.StateBlob, s.state.ProviderJSON = bytes.Clone(req.StateBlob), bytes.Clone(req.ProviderJSON)
	s.results[req.RequestID] = wire.OperationResult{StateKey: req.StateKey, RequestID: req.RequestID, InputDigest: req.InputDigest, Result: bytes.Clone(req.Result), Revision: s.state.Revision}
	if s.loseCommitAck {
		s.loseCommitAck = false
		return wire.CommitResult{}, errors.New("lost commit acknowledgement")
	}
	return wire.CommitResult{Revision: s.state.Revision, Result: bytes.Clone(req.Result)}, nil
}

func (s *integrationStore) LookupResult(_ context.Context, req wire.LookupResultRequest) (wire.OperationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, ok := s.results[req.RequestID]
	if !ok || result.StateKey != req.StateKey {
		return wire.OperationResult{}, wire.ErrNotFound
	}
	if result.InputDigest != req.InputDigest {
		return wire.OperationResult{}, wire.ErrRequestConflict
	}
	result.Result = bytes.Clone(result.Result)
	return result, nil
}

func cloneIntegrationState(state wire.StoredState) wire.StoredState {
	state.StateBlob, state.ProviderJSON = bytes.Clone(state.StateBlob), bytes.Clone(state.ProviderJSON)
	return state
}

func TestEngineNativeBackendAliasesUseTheSameProtocolAndIdentity(t *testing.T) {
	ctx := context.Background()
	store := &integrationStore{results: map[string]wire.OperationResult{}}
	owner := newIntegrationEngine(t, store, true)
	var identity []byte
	for _, scheme := range []string{engine.Scheme, engine.SchemeNative, engine.SchemeWASM} {
		t.Run(scheme, func(t *testing.T) {
			prepare := integrationRequest(wire.PrepareProfile)
			prepare.Scheme = scheme
			profile := owner.Handle(ctx, prepare)
			requireIntegrationReply(t, prepare, profile)
			if identity == nil {
				identity = bytes.Clone(profile.AgentConfig)
			}
			if !bytes.Equal(identity, profile.AgentConfig) {
				t.Fatal("alias changed the server identity")
			}
			var material struct {
				ServerKID       string `json:"server_kid"`
				ServerPublicKey []byte `json:"server_public_key"`
			}
			if err := json.Unmarshal(profile.AgentConfig, &material); err != nil {
				t.Fatal(err)
			}
			serverKID, err := strconv.ParseUint(material.ServerKID, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			client, session := beginIntegrationSessionWithScheme(t, owner, profile, serverKID, material.ServerPublicKey, scheme)
			plaintext := []byte("same Beaconcrypt wire protocol for " + scheme)
			ciphertext, err := client.EncryptToServer(plaintext)
			if err != nil {
				t.Fatal(err)
			}
			open := integrationSessionRequest(wire.Open, profile, session)
			open.Scheme, open.Message = scheme, ciphertext
			opened := owner.Handle(ctx, open)
			requireIntegrationReply(t, open, opened)
			if !bytes.Equal(opened.Message, plaintext) {
				t.Fatal("alias could not open client ciphertext")
			}
			seal := integrationSessionRequest(wire.Seal, profile, session)
			seal.Scheme, seal.Message = scheme, plaintext
			sealed := owner.Handle(ctx, seal)
			requireIntegrationReply(t, seal, sealed)
			recovered, err := client.DecryptServerMessage(sealed.Message)
			if err != nil || !bytes.Equal(recovered, plaintext) {
				t.Fatalf("alias could not decrypt sealed response: %v", err)
			}
		})
	}
}
