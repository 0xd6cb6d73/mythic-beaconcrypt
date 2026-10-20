package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	"github.com/google/uuid"
)

// memoryStore models the atomic storage contract rather than engine internals.
// Faults can lose an acknowledgement either before or after a durable commit.
type memoryStore struct {
	mu                                                    sync.Mutex
	state                                                 *wire.StoredState
	results                                               map[string]wire.OperationResult
	failCommit, loseCommitAck, failLookup, loseAcquireAck bool
	beforeAcquire                                         func()
}

func newMemoryStore() *memoryStore {
	return &memoryStore{results: make(map[string]wire.OperationResult)}
}
func cloneState(s wire.StoredState) wire.StoredState {
	s.StateBlob = bytes.Clone(s.StateBlob)
	s.ProviderJSON = bytes.Clone(s.ProviderJSON)
	return s
}
func cloneResult(r wire.OperationResult) wire.OperationResult {
	r.Result = bytes.Clone(r.Result)
	return r
}
func (s *memoryStore) Load(_ context.Context, key wire.StateKey) (wire.StoredState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil || s.state.StateKey != key {
		return wire.StoredState{}, wire.ErrNotFound
	}
	return cloneState(*s.state), nil
}
func (s *memoryStore) Create(_ context.Context, r wire.CreateStateRequest) (wire.StoredState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		return wire.StoredState{}, wire.ErrAlreadyExists
	}
	v := wire.StoredState{StateKey: r.StateKey, StateBlob: bytes.Clone(r.StateBlob), ProviderJSON: bytes.Clone(r.ProviderJSON), Revision: 1}
	s.state = &v
	return cloneState(v), nil
}
func (s *memoryStore) Acquire(_ context.Context, r wire.AcquireStateRequest) (wire.StoredState, error) {
	if s.beforeAcquire != nil {
		f := s.beforeAcquire
		s.beforeAcquire = nil
		f()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return wire.StoredState{}, wire.ErrNotFound
	}
	if r.ExpectedOwnerEpoch != s.state.OwnerEpoch {
		return wire.StoredState{}, wire.ErrStaleWriter
	}
	s.state.OwnerEpoch++
	if s.loseAcquireAck {
		s.loseAcquireAck = false
		return wire.StoredState{}, errors.New("lost acquire acknowledgement")
	}
	return cloneState(*s.state), nil
}
func (s *memoryStore) Commit(_ context.Context, r wire.CommitStateRequest) (wire.CommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.results[r.RequestID]; ok {
		if old.InputDigest != r.InputDigest {
			return wire.CommitResult{}, wire.ErrRequestConflict
		}
		return wire.CommitResult{Revision: old.Revision, Result: bytes.Clone(old.Result), Cached: true}, nil
	}
	if s.state == nil {
		return wire.CommitResult{}, wire.ErrNotFound
	}
	if r.OwnerEpoch != s.state.OwnerEpoch || r.ExpectedRevision != s.state.Revision {
		return wire.CommitResult{}, wire.ErrStaleWriter
	}
	if s.failCommit {
		s.failCommit = false
		return wire.CommitResult{}, errors.New("commit not delivered")
	}
	s.state.Revision++
	s.state.StateBlob = bytes.Clone(r.StateBlob)
	s.state.ProviderJSON = bytes.Clone(r.ProviderJSON)
	result := wire.OperationResult{StateKey: r.StateKey, RequestID: r.RequestID, InputDigest: r.InputDigest, Result: bytes.Clone(r.Result), Revision: s.state.Revision}
	s.results[r.RequestID] = result
	if s.loseCommitAck {
		s.loseCommitAck = false
		return wire.CommitResult{}, errors.New("lost commit acknowledgement")
	}
	return wire.CommitResult{Revision: result.Revision, Result: bytes.Clone(result.Result)}, nil
}
func (s *memoryStore) LookupResult(_ context.Context, r wire.LookupResultRequest) (wire.OperationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failLookup {
		return wire.OperationResult{}, errors.New("lookup unavailable")
	}
	v, ok := s.results[r.RequestID]
	if !ok {
		return wire.OperationResult{}, wire.ErrNotFound
	}
	if v.InputDigest != r.InputDigest {
		return wire.OperationResult{}, wire.ErrRequestConflict
	}
	return cloneResult(v), nil
}

type fakeState struct {
	PublicKey                    []byte
	Generation, Counter, NextKID uint64
}
type fakeFactory struct {
	newCalls, restoreCalls, registerCalls, encryptCalls, decryptCalls, closeCalls           int
	initial                                                                                 []byte
	failSend, failReceive, failRegistration, advanceFailure, badAuthenticatedID, failExport bool
	failPersistence                                                                         bool
}

func (f *fakeFactory) nativeError(message string) error {
	if f.failPersistence {
		return fmt.Errorf("%w: %s", ErrNativePersistence, message)
	}
	return errors.New(message)
}

type fakeNative struct {
	f      *fakeFactory
	state  fakeState
	closed bool
}

func (f *fakeFactory) New(_ uint64) (Native, error) {
	f.newCalls++
	return &fakeNative{f: f, state: fakeState{PublicKey: []byte("stable-test-public-key"), NextKID: 10}}, nil
}
func (f *fakeFactory) Restore(b []byte) (Native, error) {
	f.restoreCalls++
	var state fakeState
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, err
	}
	state.Generation++
	return &fakeNative{f: f, state: state}, nil
}
func (f *fakeFactory) SenderKeyID(b []byte) (uint64, error) {
	head, _, ok := strings.Cut(string(b), "|")
	if !ok {
		return 0, errors.New("malformed packet")
	}
	return strconv.ParseUint(head, 10, 64)
}
func (n *fakeNative) IdentityPK() ([]byte, error) { return bytes.Clone(n.state.PublicKey), nil }
func (n *fakeNative) Register(_, initial []byte) (Registration, error) {
	n.f.registerCalls++
	n.f.initial = bytes.Clone(initial)
	if n.f.failRegistration {
		if n.f.advanceFailure {
			n.state.Counter++
		}
		return Registration{}, n.f.nativeError("registration failed")
	}
	n.state.Counter++
	n.state.NextKID++
	return Registration{Data: []byte("native-registration-reply"), KeyID: n.state.NextKID}, nil
}
func (n *fakeNative) Encrypt(key uint64, plaintext []byte) (Update, error) {
	if n.closed {
		panic("closed native reused")
	}
	n.f.encryptCalls++
	if n.f.failSend {
		if n.f.advanceFailure {
			n.state.Counter++
		}
		return Update{}, n.f.nativeError("native send failed")
	}
	n.state.Counter++
	actual := key
	if n.f.badAuthenticatedID {
		actual++
	}
	return Update{Data: []byte(fmt.Sprintf("send:%d:%d:%s", key, n.state.Counter, plaintext)), KeyID: actual, Seq: n.state.Counter}, nil
}
func (n *fakeNative) Decrypt(packet []byte) (Update, error) {
	if n.closed {
		panic("closed native reused")
	}
	n.f.decryptCalls++
	if n.f.failReceive {
		if n.f.advanceFailure {
			n.state.Counter++
		}
		return Update{}, n.f.nativeError("native receive failed")
	}
	key, err := n.f.SenderKeyID(packet)
	if err != nil {
		return Update{}, err
	}
	_, message, _ := strings.Cut(string(packet), "|")
	n.state.Counter++
	if n.f.badAuthenticatedID {
		key++
	}
	return Update{Data: []byte(message), KeyID: key, Seq: n.state.Counter}, nil
}
func (n *fakeNative) Export() ([]byte, error) {
	if n.f.failExport {
		return nil, errors.New("export failed")
	}
	return json.Marshal(n.state)
}
func (n *fakeNative) Close() {
	if !n.closed {
		n.f.closeCalls++
		n.closed = true
	}
}

func testEngine(t *testing.T, config Config) (*Engine, *fakeFactory, *memoryStore) {
	t.Helper()
	factory, store := &fakeFactory{}, newMemoryStore()
	config.Initialize = true
	e, err := New(config, factory, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e, factory, store
}
func testRequest(method string) wire.Request {
	return wire.Request{APIVersion: wire.APIVersion, RequestID: uuid.NewString(), OperationScopeID: 7, Method: method, AuthContext: "ephemeral-auth"}
}
func mustHandle(t *testing.T, e *Engine, r wire.Request) wire.Response {
	t.Helper()
	v := e.Handle(context.Background(), r)
	if !v.Success {
		t.Fatalf("%s failed: %+v", r.Method, v.Error)
	}
	if err := v.Validate(r); err != nil {
		t.Fatal(err)
	}
	return v
}
func prepare(t *testing.T, e *Engine) wire.Response {
	t.Helper()
	r := testRequest(wire.PrepareProfile)
	r.Scheme = Scheme
	return mustHandle(t, e, r)
}
func beginRequest(p wire.Response) wire.Request {
	r := testRequest(wire.BeginSession)
	r.ProfileRef = p.ProfileRef
	r.PayloadUUID = uuid.NewString()
	r.NextUUID = uuid.NewString()
	r.Namespace = p.Namespace
	r.StateID = p.StateID
	r.Message = []byte(`{"action":"staging","session_id":"client-handshake","data":"` + base64.StdEncoding.EncodeToString([]byte("registration")) + `"}`)
	return r
}
func beginSession(t *testing.T, e *Engine, p wire.Response) wire.Response {
	t.Helper()
	return mustHandle(t, e, beginRequest(p))
}
func sessionRequest(method string, p, s wire.Response, message []byte) wire.Request {
	r := testRequest(method)
	r.ProfileRef = p.ProfileRef
	r.SessionRef = s.SessionRef
	r.Namespace = s.Namespace
	r.StateID = s.StateID
	r.Message = message
	return r
}
func requireFailure(t *testing.T, r wire.Response, code, outcome string) {
	t.Helper()
	if r.Success || r.Error == nil || r.Error.Code != code || r.Error.Outcome != outcome {
		t.Fatalf("wanted %s/%s, got %+v", code, outcome, r)
	}
}

func TestProfileStagingAndScopedIdempotentResult(t *testing.T) {
	e, f, store := testEngine(t, Config{})
	p := prepare(t, e)
	var material struct {
		Version   int    `json:"version"`
		ServerKID string `json:"server_kid"`
		PublicKey []byte `json:"server_public_key"`
	}
	if err := json.Unmarshal(p.AgentConfig, &material); err != nil || material.Version != 1 || material.ServerKID != "0" || !bytes.Equal(material.PublicKey, []byte("stable-test-public-key")) {
		t.Fatalf("invalid build material %s %v", p.AgentConfig, err)
	}
	if p.EncKey == nil || p.DecKey == nil || !bytes.Equal(*p.EncKey, p.AgentConfig) || !bytes.Equal(*p.DecKey, p.AgentConfig) {
		t.Fatal("compatibility material differs")
	}
	begin := beginRequest(p)
	s := mustHandle(t, e, begin)
	var initial, outer map[string]any
	_ = json.Unmarshal(f.initial, &initial)
	_ = json.Unmarshal(s.Message, &outer)
	if initial["uuid"] != begin.NextUUID || initial["status"] != "success" || initial["session_id"] != "client-handshake" || outer["uuid"] != begin.NextUUID || outer["session_id"] != "client-handshake" {
		t.Fatalf("staging claims not preserved: %+v %+v", initial, outer)
	}
	send := sessionRequest(wire.Seal, p, s, []byte("hello"))
	first := mustHandle(t, e, send)
	send.AuthContext = "fresh-auth"
	again := mustHandle(t, e, send)
	if !bytes.Equal(first.Message, again.Message) || again.AuthContext != "fresh-auth" || f.encryptCalls != 1 {
		t.Fatal("retry advanced native state or reused auth")
	}
	stored := store.results[send.RequestID]
	if bytes.Contains(stored.Result, []byte("auth_context")) {
		t.Fatal("transient authorization persisted")
	}
	conflict := send
	conflict.Message = []byte("changed")
	requireFailure(t, e.Handle(context.Background(), conflict), "request_conflict", "rejected")
	lookup := testRequest(wire.GetOperation)
	lookup.LookupRequestID = send.RequestID
	lookup.AuthContext = "lookup-auth"
	result := mustHandle(t, e, lookup)
	if !bytes.Equal(result.Message, first.Message) || result.RequestID != lookup.RequestID || result.AuthContext != lookup.AuthContext {
		t.Fatal("lookup failed to correlate recovered result")
	}
	lookup.RequestID = uuid.NewString()
	lookup.OperationScopeID++
	requireFailure(t, e.Handle(context.Background(), lookup), "unavailable_session", "rejected")
	cross := send
	cross.OperationScopeID++
	requireFailure(t, e.Handle(context.Background(), cross), "request_conflict", "rejected")
}

func TestWrongSessionPrecheckAndRejectedJunkDoNotConsumeAdmission(t *testing.T) {
	e, f, _ := testEngine(t, Config{MaxRequests: 8})
	p := prepare(t, e)
	s1 := beginSession(t, e, p)
	s2 := beginSession(t, e, p)
	for i := 0; i < 30; i++ {
		r := beginRequest(p)
		r.Message = []byte(`{"action":"wrong"}`)
		requireFailure(t, e.Handle(context.Background(), r), "invalid_input", "rejected")
		r = sessionRequest(wire.Open, p, s1, []byte("12|packet"))
		requireFailure(t, e.Handle(context.Background(), r), "route_mismatch", "rejected")
	}
	if f.decryptCalls != 0 || len(e.data.Requests) != 3 {
		t.Fatalf("junk used native or capacity: calls=%d requests=%d", f.decryptCalls, len(e.data.Requests))
	}
	right := sessionRequest(wire.Open, p, s2, []byte("12|packet"))
	r := mustHandle(t, e, right)
	if string(r.Message) != "packet" || f.decryptCalls != 1 {
		t.Fatal("properly routed packet could not be opened")
	}
}

func TestLostCommitAcknowledgementRecoversImmutableResult(t *testing.T) {
	e, f, store := testEngine(t, Config{})
	p := prepare(t, e)
	s := beginSession(t, e, p)
	send := sessionRequest(wire.Seal, p, s, []byte("hello"))
	store.loseCommitAck = true
	first := mustHandle(t, e, send)
	if e.native != nil {
		t.Fatal("ambiguous handle was retained")
	}
	again := mustHandle(t, e, send)
	if !bytes.Equal(first.Message, again.Message) || f.encryptCalls != 1 {
		t.Fatal("lost commit reply caused a second send")
	}
	if e.native == nil || f.restoreCalls < 2 {
		t.Fatal("owner was not restored after ambiguous commit")
	}
	mustHandle(t, e, sessionRequest(wire.Seal, p, s, []byte("next")))
	if e.data.Sessions[s.SessionRef].UnresolvedRequestID != "" || f.encryptCalls != 2 {
		t.Fatal("lost successful commit acknowledgement fenced the session")
	}
}

func TestUncommittedNativeOutputIsDiscardedAndRetryRestores(t *testing.T) {
	e, f, store := testEngine(t, Config{})
	p := prepare(t, e)
	s := beginSession(t, e, p)
	send := sessionRequest(wire.Seal, p, s, []byte("hello"))
	store.failCommit = true
	failed := e.Handle(context.Background(), send)
	requireFailure(t, failed, "storage_unavailable", "unresolved")
	if len(failed.Message) != 0 || e.native != nil {
		t.Fatal("uncommitted output or dirty owner escaped")
	}
	recovered := mustHandle(t, e, send)
	if f.encryptCalls != 2 || !strings.Contains(string(recovered.Message), ":2:hello") {
		t.Fatalf("retry did not restore last committed state: %s calls=%d", recovered.Message, f.encryptCalls)
	}
}

func TestRevocationSurvivesRestartAndBlocksCachedPlaintext(t *testing.T) {
	e, f, store := testEngine(t, Config{})
	p := prepare(t, e)
	s := beginSession(t, e, p)
	open := sessionRequest(wire.Open, p, s, []byte("11|secret"))
	mustHandle(t, e, open)
	revoke := sessionRequest(wire.RevokeSession, p, s, nil)
	mustHandle(t, e, revoke)
	requireFailure(t, e.Handle(context.Background(), open), "unavailable_session", "rejected")
	lookup := testRequest(wire.GetOperation)
	lookup.LookupRequestID = open.RequestID
	requireFailure(t, e.Handle(context.Background(), lookup), "unavailable_session", "rejected")
	e.Close()
	restored, err := New(Config{}, f, store)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err = restored.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireFailure(t, restored.Handle(context.Background(), open), "unavailable_session", "rejected")
	mustHandle(t, restored, revoke)
}

func TestNativeFailureOutcomesAndRetirement(t *testing.T) {
	for _, advance := range []bool{false, true} {
		t.Run(strconv.FormatBool(advance), func(t *testing.T) {
			e, f, store := testEngine(t, Config{})
			p := prepare(t, e)
			s := beginSession(t, e, p)
			r := sessionRequest(wire.Open, p, s, []byte("11|packet"))
			f.failReceive = true
			f.advanceFailure = advance
			failed := e.Handle(context.Background(), r)
			outcome := "rejected"
			if advance {
				outcome = "unresolved"
			}
			requireFailure(t, failed, "native_failure", outcome)
			if e.native != nil {
				t.Fatal("failed native handle retained")
			}
			_, journaled := store.results[r.RequestID]
			if journaled != advance {
				t.Fatalf("rejected junk journaled or advanced effect lost: %v", journaled)
			}
			f.failReceive = false
			f.advanceFailure = false
			if advance {
				again := e.Handle(context.Background(), r)
				requireFailure(t, again, "native_failure", "unresolved")
				if f.decryptCalls != 1 {
					t.Fatal("advanced failed receive executed again")
				}
			}
			next := sessionRequest(wire.Open, p, s, []byte("11|next"))
			if advance {
				requireFailure(t, e.Handle(context.Background(), next), "session_unresolved", "unresolved")
			} else {
				mustHandle(t, e, next)
			}
		})
	}
}

// An unresolved native outcome belongs to the provider's session metadata. It
// survives a worker restart without relying on a Mythic binding-side marker.
func TestNativeFailureFencesOnlyItsSessionAcrossRestart(t *testing.T) {
	for _, method := range []string{wire.Open, wire.Seal} {
		for _, persistence := range []bool{false, true} {
			t.Run(method+"/persistence="+strconv.FormatBool(persistence), func(t *testing.T) {
				e, f, store := testEngine(t, Config{})
				p := prepare(t, e)
				s := beginSession(t, e, p)
				unaffected := beginSession(t, e, p)
				r := sessionRequest(method, p, s, []byte("11|packet"))
				f.failReceive, f.failSend = method == wire.Open, method == wire.Seal
				// Typed persistence failure is unresolved even with unchanged bytes;
				// an ordinary native failure is unresolved when it advances state.
				f.failPersistence, f.advanceFailure = persistence, !persistence
				failed := e.Handle(context.Background(), r)
				code := "native_failure"
				if persistence {
					code = "native_persistence_failure"
				}
				requireFailure(t, failed, code, "unresolved")
				var stored ownerData
				if err := json.Unmarshal(store.state.ProviderJSON, &stored); err != nil {
					t.Fatal(err)
				}
				if stored.Sessions[s.SessionRef].UnresolvedRequestID != r.RequestID || stored.Sessions[unaffected.SessionRef].UnresolvedRequestID != "" {
					t.Fatal("native failure was not committed exclusively on its session")
				}
				if e.native != nil {
					t.Fatal("ambiguous native handle was retained")
				}
				e.Close()
				f.failReceive, f.failSend, f.failPersistence, f.advanceFailure = false, false, false, false
				restored, err := New(Config{}, f, store)
				if err != nil {
					t.Fatal(err)
				}
				defer restored.Close()
				if err = restored.Activate(context.Background()); err != nil {
					t.Fatal(err)
				}
				before := f.decryptCalls + f.encryptCalls
				for _, freshMethod := range []string{wire.Open, wire.Seal} {
					fresh := sessionRequest(freshMethod, p, s, []byte("11|fresh"))
					requireFailure(t, restored.Handle(context.Background(), fresh), "session_unresolved", "unresolved")
				}
				r.AuthContext = "renewed-auth"
				replayed := restored.Handle(context.Background(), r)
				requireFailure(t, replayed, code, "unresolved")
				if replayed.AuthContext != r.AuthContext {
					t.Fatal("failure replay retained its old authorization context")
				}
				lookup := testRequest(wire.GetOperation)
				lookup.LookupRequestID = r.RequestID
				requireFailure(t, restored.Handle(context.Background(), lookup), code, "unresolved")
				if f.decryptCalls+f.encryptCalls != before {
					t.Fatal("blocked work or exact failure replay reached native code")
				}
				mustHandle(t, restored, sessionRequest(wire.Open, p, unaffected, []byte("12|unaffected")))
				mustHandle(t, restored, sessionRequest(wire.Seal, p, unaffected, []byte("unaffected")))
				mustHandle(t, restored, sessionRequest(wire.RevokeSession, p, s, nil))
				replacement := beginSession(t, restored, p)
				mustHandle(t, restored, sessionRequest(wire.Seal, p, replacement, []byte("reestablished")))
			})
		}
	}
}

func TestNativePersistenceFailureIsUnresolvedEvenWithUnchangedCheckpoint(t *testing.T) {
	for _, method := range []string{wire.Open, wire.Seal, wire.BeginSession} {
		for _, advance := range []bool{false, true} {
			t.Run(method+"/advance="+strconv.FormatBool(advance), func(t *testing.T) {
				e, f, store := testEngine(t, Config{})
				p := prepare(t, e)
				s := beginSession(t, e, p)
				r := sessionRequest(method, p, s, []byte("11|packet"))
				if method == wire.BeginSession {
					r = beginRequest(p)
				}
				before := bytes.Clone(store.state.StateBlob)
				f.failPersistence, f.advanceFailure = true, advance
				f.failReceive = method == wire.Open
				f.failSend = method == wire.Seal
				f.failRegistration = method == wire.BeginSession
				failed := e.Handle(context.Background(), r)
				requireFailure(t, failed, "native_persistence_failure", "unresolved")
				if len(failed.Message) != 0 || e.native != nil {
					t.Fatal("native persistence failure released output or retained its owner")
				}
				if _, journaled := store.results[r.RequestID]; !journaled {
					t.Fatal("unresolved persistence outcome was not recorded immutably")
				}
				if unchanged := bytes.Equal(before, store.state.StateBlob); unchanged == advance {
					t.Fatal("test did not exercise the requested checkpoint-change condition")
				}
				calls := f.decryptCalls + f.encryptCalls + f.registerCalls
				again := e.Handle(context.Background(), r)
				requireFailure(t, again, "native_persistence_failure", "unresolved")
				if f.decryptCalls+f.encryptCalls+f.registerCalls != calls {
					t.Fatal("immutable persistence failure re-executed a native operation")
				}
			})
		}
	}
}

func TestAuthenticatedIdentityMismatchNeverReturnsPlaintext(t *testing.T) {
	e, f, store := testEngine(t, Config{})
	p := prepare(t, e)
	s := beginSession(t, e, p)
	r := sessionRequest(wire.Open, p, s, []byte("11|sensitive"))
	f.badAuthenticatedID = true
	failed := e.Handle(context.Background(), r)
	requireFailure(t, failed, "identity_mismatch", "unresolved")
	if len(failed.Message) != 0 || e.native != nil {
		t.Fatal("mismatched plaintext or handle escaped")
	}
	if _, ok := store.results[r.RequestID]; !ok {
		t.Fatal("native effect not checkpointed")
	}
}

func TestExclusiveOwnerFencingAndLostAcquireAcknowledgement(t *testing.T) {
	t.Run("takeover", func(t *testing.T) {
		e, f, store := testEngine(t, Config{})
		p := prepare(t, e)
		s := beginSession(t, e, p)
		other, err := New(Config{}, f, store)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		if err = other.Activate(context.Background()); err != nil {
			t.Fatal(err)
		}
		failed := e.Handle(context.Background(), sessionRequest(wire.Seal, p, s, []byte("hello")))
		requireFailure(t, failed, "stale_owner", "unresolved")
		if f.encryptCalls != 0 || !e.fenced {
			t.Fatal("replaced worker performed native work")
		}
		requireFailure(t, e.Handle(context.Background(), testRequest(wire.Describe)), "owner_unavailable", "unresolved")
	})
	t.Run("lost acquire", func(t *testing.T) {
		e, f, store := testEngine(t, Config{})
		e.Close()
		other, err := New(Config{}, f, store)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		before := f.restoreCalls
		store.loseAcquireAck = true
		if err = other.Activate(context.Background()); err == nil {
			t.Fatal("lost acquire acknowledgement accepted")
		}
		if f.restoreCalls != before || !other.fenced {
			t.Fatal("uncertain ownership restored native state")
		}
		if err = other.Activate(context.Background()); !errors.Is(err, wire.ErrStaleWriter) {
			t.Fatalf("uncertain worker reacquired: %v", err)
		}
	})
}

func TestAcquireUsesAtomicallyAcquiredMetadata(t *testing.T) {
	e, f, store := testEngine(t, Config{})
	e.Close()
	replacement, err := New(Config{}, f, store)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	newProfile := uuid.NewString()
	store.beforeAcquire = func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		var d ownerData
		_ = json.Unmarshal(store.state.ProviderJSON, &d)
		d.Profiles[newProfile] = profile{OperationID: 7}
		store.state.ProviderJSON, _ = json.Marshal(d)
		store.state.Revision++
	}
	if err = replacement.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := replacement.data.Profiles[newProfile]; !ok {
		t.Fatal("activation replaced newly committed mappings with pre-acquire metadata")
	}
}

func TestInitializeIsExplicitCreateOnlyAndMissingStateNeverRekeys(t *testing.T) {
	factory, store := &fakeFactory{}, newMemoryStore()
	normal, err := New(Config{}, factory, store)
	if err != nil {
		t.Fatal(err)
	}
	defer normal.Close()
	if err = normal.Activate(context.Background()); err == nil || factory.newCalls != 0 {
		t.Fatal("missing state auto-created identity")
	}
	e, _, existing := testEngine(t, Config{})
	e.Close()
	another, err := New(Config{Initialize: true}, factory, existing)
	if err != nil {
		t.Fatal(err)
	}
	defer another.Close()
	if err = another.Activate(context.Background()); !errors.Is(err, wire.ErrAlreadyExists) {
		t.Fatalf("initializer replaced existing identity: %v", err)
	}
}

func TestSessionAdmissionAndConcurrentSends(t *testing.T) {
	e, f, _ := testEngine(t, Config{MaxSessions: 1})
	p := prepare(t, e)
	s := beginSession(t, e, p)
	requireFailure(t, e.Handle(context.Background(), beginRequest(p)), "capacity", "rejected")
	if f.registerCalls != 1 {
		t.Fatal("capacity checked after native registration")
	}
	const count = 20
	var wg sync.WaitGroup
	out := make(chan wire.Response, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out <- e.Handle(context.Background(), sessionRequest(wire.Seal, p, s, []byte(strconv.Itoa(i))))
		}(i)
	}
	wg.Wait()
	close(out)
	seen := map[string]bool{}
	for response := range out {
		if !response.Success {
			t.Fatalf("concurrent send failed: %+v", response.Error)
		}
		if seen[string(response.Message)] {
			t.Fatal("native counter reused")
		}
		seen[string(response.Message)] = true
	}
	if f.encryptCalls != count {
		t.Fatalf("wrong native send count %d", f.encryptCalls)
	}
}

func TestExportFailureNeverReturnsOutput(t *testing.T) {
	e, f, _ := testEngine(t, Config{})
	p := prepare(t, e)
	s := beginSession(t, e, p)
	f.failExport = true
	result := e.Handle(context.Background(), sessionRequest(wire.Seal, p, s, []byte("hello")))
	requireFailure(t, result, "checkpoint_unavailable", "unresolved")
	if len(result.Message) != 0 || e.native != nil {
		t.Fatal("unexported result escaped")
	}
}

func TestStagingRetryAndOperationClaims(t *testing.T) {
	e, f, _ := testEngine(t, Config{})
	p := prepare(t, e)
	r := beginRequest(p)
	first := mustHandle(t, e, r)
	r.AuthContext = "renewed-auth"
	again := mustHandle(t, e, r)
	if f.registerCalls != 1 || first.SessionRef != again.SessionRef || !bytes.Equal(first.Message, again.Message) {
		t.Fatal("staging retry registered another session")
	}
	other := beginRequest(p)
	other.OperationScopeID++
	requireFailure(t, e.Handle(context.Background(), other), "unavailable_session", "rejected")
	open := sessionRequest(wire.Open, p, first, []byte("11|message"))
	open.OperationScopeID++
	requireFailure(t, e.Handle(context.Background(), open), "unavailable_session", "rejected")
	wrongState := sessionRequest(wire.Seal, p, first, []byte("message"))
	wrongState.StateID = "another-owner"
	requireFailure(t, e.Handle(context.Background(), wrongState), "unavailable_session", "rejected")
	if f.registerCalls != 1 || f.encryptCalls != 0 || f.decryptCalls != 0 {
		t.Fatal("unauthorized claims reached native operations")
	}
}

func TestRestoreRejectsIdentityMetadataMismatch(t *testing.T) {
	e, f, store := testEngine(t, Config{})
	e.Close()
	store.mu.Lock()
	var data ownerData
	_ = json.Unmarshal(store.state.ProviderJSON, &data)
	data.IdentityPK = []byte("wrong-public-key")
	store.state.ProviderJSON, _ = json.Marshal(data)
	store.mu.Unlock()
	other, err := New(Config{}, f, store)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = other.Activate(context.Background()); err == nil {
		t.Fatal("mismatched identity accepted")
	}
	if other.native != nil {
		t.Fatal("unverified owner retained")
	}
}

func TestMissingIndexedResultCannotReexecuteNative(t *testing.T) {
	e, f, store := testEngine(t, Config{})
	p := prepare(t, e)
	s := beginSession(t, e, p)
	r := sessionRequest(wire.Seal, p, s, []byte("message"))
	mustHandle(t, e, r)
	store.mu.Lock()
	delete(store.results, r.RequestID)
	store.mu.Unlock()
	requireFailure(t, e.Handle(context.Background(), r), "result_unavailable", "unresolved")
	if f.encryptCalls != 1 {
		t.Fatal("missing immutable result caused native reexecution")
	}
}

func TestReadOnlyQueriesDoNotConsumeAdmissionOrFreezeUnknownResult(t *testing.T) {
	e, _, store := testEngine(t, Config{MaxRequests: 3})
	p := prepare(t, e)
	s := beginSession(t, e, p)
	for i := 0; i < 30; i++ {
		mustHandle(t, e, testRequest(wire.Describe))
	}
	target := sessionRequest(wire.Seal, p, s, []byte("later"))
	query := testRequest(wire.GetOperation)
	query.LookupRequestID = target.RequestID
	requireFailure(t, e.Handle(context.Background(), query), "result_unavailable", "unresolved")
	if len(e.data.Requests) != 2 {
		t.Fatalf("read queries consumed request slots: %d", len(e.data.Requests))
	}
	committed := mustHandle(t, e, target)
	recovered := mustHandle(t, e, query)
	if !bytes.Equal(committed.Message, recovered.Message) {
		t.Fatal("same lookup request did not observe later target commit")
	}
	if len(e.data.Requests) != 3 {
		t.Fatal("lookup persisted a new request index")
	}
	if _, ok := store.results[query.RequestID]; ok {
		t.Fatal("lookup journaled duplicate result")
	}
}

func TestProviderMessageLimitMatchesCompleteFrameBudget(t *testing.T) {
	if _, err := New(Config{MaxMessageBytes: MaxProviderMessageBytes + 1}, &fakeFactory{}, newMemoryStore()); err == nil {
		t.Fatal("accepted a message limit above the complete Beaconcrypt frame budget")
	}
	e, err := New(Config{MaxMessageBytes: MaxProviderMessageBytes}, &fakeFactory{}, newMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Capabilities().MaxMessageBytes != 32<<20 {
		t.Fatal("complete frame limit was not advertised")
	}
}

func TestFirstRevocationHasReservedJournalSlot(t *testing.T) {
	e, f, store := testEngine(t, Config{MaxRequests: 2})
	p := prepare(t, e)
	s := beginSession(t, e, p)
	requireFailure(t, e.Handle(context.Background(), sessionRequest(wire.Seal, p, s, []byte("full"))), "capacity", "rejected")
	revoke := sessionRequest(wire.RevokeSession, p, s, nil)
	mustHandle(t, e, revoke)
	if ordinaryRequestCount(e.data) != 2 || len(e.data.Requests) != 3 || f.encryptCalls != 0 {
		t.Fatal("first revocation did not use its reserved slot")
	}
	count := len(e.data.Requests)
	requireFailure(t, e.Handle(context.Background(), sessionRequest(wire.RevokeSession, p, s, nil)), "already_revoked", "rejected")
	if len(e.data.Requests) != count {
		t.Fatal("repeated revocation allocated another receipt")
	}
	lookup := testRequest(wire.GetOperation)
	lookup.LookupRequestID = revoke.RequestID
	mustHandle(t, e, lookup)
	e.Close()
	restored, err := New(Config{MaxRequests: 2}, f, store)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err = restored.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	mustHandle(t, restored, revoke)
	requireFailure(t, restored.Handle(context.Background(), sessionRequest(wire.Seal, p, s, []byte("revoked"))), "unavailable_session", "rejected")
}

func TestFirstRevocationHasReservedMetadataSpace(t *testing.T) {
	e, f, store := testEngine(t, Config{MaxRequests: 100000})
	p := prepare(t, e)
	s := beginSession(t, e, p)
	// Seed a realistic journal just below the storage envelope limit, then use
	// public operations to reach normal admission exhaustion. Results for the
	// fixture entries are irrelevant because none of those IDs are queried.
	index := requestIndex{Digest: strings.Repeat("0", 64), OperationID: 7, Method: wire.Seal, SessionRef: s.SessionRef}
	entry, err := json.Marshal(map[string]requestIndex{uuid.Nil.String(): index})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := json.Marshal(e.data)
	if err != nil {
		t.Fatal(err)
	}
	count := (wire.MaxProviderJSONBytes - len(initial) - 2048) / (len(entry) - 1)
	for i := 0; i < count; i++ {
		e.data.Requests[uuid.NewString()] = index
	}
	seeded, err := json.Marshal(e.data)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.ProviderJSON = bytes.Clone(seeded)
	store.mu.Unlock()
	e.head.ProviderJSON = seeded
	exhausted := false
	for i := 0; i < 20; i++ {
		before := f.encryptCalls
		response := e.Handle(context.Background(), sessionRequest(wire.Seal, p, s, []byte("fill")))
		if !response.Success {
			requireFailure(t, response, "capacity", "rejected")
			if f.encryptCalls != before {
				t.Fatal("metadata capacity checked after native send")
			}
			exhausted = true
			break
		}
	}
	if !exhausted {
		t.Fatal("fixture did not reach metadata admission limit")
	}
	revoke := sessionRequest(wire.RevokeSession, p, s, nil)
	mustHandle(t, e, revoke)
	saved, err := store.Load(context.Background(), e.key)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.ProviderJSON) > wire.MaxProviderJSONBytes {
		t.Fatal("revocation exceeded storage metadata limit")
	}
	e.Close()
	restored, err := New(Config{MaxRequests: 100000}, f, store)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err = restored.Activate(context.Background()); err != nil {
		t.Fatalf("full revoked journal failed to restore: %v", err)
	}
	mustHandle(t, restored, revoke)
}

func TestRestoreRejectsMissingRevocationReserveAndDuplicateReceipts(t *testing.T) {
	t.Run("no metadata reserve", func(t *testing.T) {
		e, f, store := testEngine(t, Config{MaxRequests: 100000})
		p := prepare(t, e)
		s := beginSession(t, e, p)
		index := requestIndex{Digest: strings.Repeat("0", 64), OperationID: 7, Method: wire.Seal, SessionRef: s.SessionRef}
		initial, err := json.Marshal(e.data)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := json.Marshal(map[string]requestIndex{uuid.Nil.String(): index})
		if err != nil {
			t.Fatal(err)
		}
		count := (wire.MaxProviderJSONBytes - len(initial)) / (len(entry) - 1)
		for i := 0; i < count; i++ {
			e.data.Requests[uuid.NewString()] = index
		}
		encoded, err := json.Marshal(e.data)
		if err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		store.state.ProviderJSON = encoded
		store.mu.Unlock()
		e.Close()
		restored, err := New(Config{MaxRequests: 100000}, f, store)
		if err != nil {
			t.Fatal(err)
		}
		defer restored.Close()
		if err = restored.Activate(context.Background()); err == nil {
			t.Fatal("restored active sessions without reserved metadata space")
		}
	})
	t.Run("duplicate revocation receipts", func(t *testing.T) {
		e, f, store := testEngine(t, Config{})
		p := prepare(t, e)
		s := beginSession(t, e, p)
		r := sessionRequest(wire.RevokeSession, p, s, nil)
		mustHandle(t, e, r)
		e.data.Requests[uuid.NewString()] = e.data.Requests[r.RequestID]
		encoded, err := json.Marshal(e.data)
		if err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		store.state.ProviderJSON = encoded
		store.mu.Unlock()
		e.Close()
		restored, err := New(Config{}, f, store)
		if err != nil {
			t.Fatal(err)
		}
		defer restored.Close()
		if err = restored.Activate(context.Background()); err == nil {
			t.Fatal("accepted more than one reserved receipt for a session")
		}
	})
}
