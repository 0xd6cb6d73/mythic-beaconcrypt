package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	"github.com/google/uuid"
)

// Each row uses the same atomic/fault-injectable store as the engine tests;
// routing here models Mythic's independent namespace/state_id records.
type campaignMemoryStore struct {
	mu           sync.Mutex
	rows         map[wire.StateKey]*memoryStore
	beforeCommit func(context.Context, wire.CommitStateRequest)
}

func newCampaignMemoryStore() *campaignMemoryStore {
	return &campaignMemoryStore{rows: make(map[wire.StateKey]*memoryStore)}
}
func (s *campaignMemoryStore) row(key wire.StateKey) *memoryStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[key] == nil {
		s.rows[key] = newMemoryStore()
	}
	return s.rows[key]
}
func (s *campaignMemoryStore) Load(ctx context.Context, key wire.StateKey) (wire.StoredState, error) {
	return s.row(key).Load(ctx, key)
}
func (s *campaignMemoryStore) Create(ctx context.Context, r wire.CreateStateRequest) (wire.StoredState, error) {
	return s.row(r.StateKey).Create(ctx, r)
}
func (s *campaignMemoryStore) Acquire(ctx context.Context, r wire.AcquireStateRequest) (wire.StoredState, error) {
	return s.row(r.StateKey).Acquire(ctx, r)
}
func (s *campaignMemoryStore) Commit(ctx context.Context, r wire.CommitStateRequest) (wire.CommitResult, error) {
	if s.beforeCommit != nil {
		s.beforeCommit(ctx, r)
	}
	return s.row(r.StateKey).Commit(ctx, r)
}
func (s *campaignMemoryStore) LookupResult(ctx context.Context, r wire.LookupResultRequest) (wire.OperationResult, error) {
	return s.row(r.StateKey).LookupResult(ctx, r)
}

// Separate fake native factories give each owner independent mutable counters,
// just as separate Beaconcrypt handles do, without serializing native calls.
type campaignFactory struct {
	mu      sync.Mutex
	created int
}

func (f *campaignFactory) New(kid uint64) (Native, error) {
	f.mu.Lock()
	f.created++
	identity := []byte(fmt.Sprintf("campaign-identity-%d", f.created))
	f.mu.Unlock()
	native, err := (&fakeFactory{}).New(kid)
	if err == nil {
		native.(*fakeNative).state.PublicKey = identity
	}
	return native, err
}
func (f *campaignFactory) Restore(checkpoint []byte) (Native, error) {
	return (&fakeFactory{}).Restore(checkpoint)
}
func (f *campaignFactory) SenderKeyID(packet []byte) (uint64, error) {
	return (&fakeFactory{}).SenderKeyID(packet)
}

func testCampaigns(t *testing.T, config Config, store *campaignMemoryStore, factory *campaignFactory) *Campaigns {
	t.Helper()
	owners, err := NewCampaigns(config, factory, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owners.Close)
	return owners
}
func mustCampaign(t *testing.T, owners *Campaigns, request wire.Request) wire.Response {
	t.Helper()
	response := owners.Handle(context.Background(), request)
	if !response.Success {
		t.Fatalf("campaign %d %s failed: %+v", request.OperationScopeID, request.Method, response.Error)
	}
	if err := response.Validate(request); err != nil {
		t.Fatal(err)
	}
	return response
}
func campaignPrepare(operationID int) wire.Request {
	request := testRequest(wire.PrepareProfile)
	request.OperationScopeID, request.Scheme = operationID, Scheme
	return request
}
func campaignBegin(profile wire.Response) wire.Request {
	request := beginRequest(profile)
	request.OperationScopeID = profile.OperationScopeID
	return request
}
func campaignSeal(session wire.Response) wire.Request {
	request := testRequest(wire.Seal)
	request.OperationScopeID = session.OperationScopeID
	request.SessionRef, request.Namespace, request.StateID = session.SessionRef, session.Namespace, session.StateID
	request.Message = []byte("campaign message")
	return request
}

func TestCampaignsIsolateIdentityStateAndJournal(t *testing.T) {
	store, factory := newCampaignMemoryStore(), &campaignFactory{}
	owners := testCampaigns(t, Config{Namespace: "test", StateID: "owner", MaxRequests: 2}, store, factory)
	first, second := campaignPrepare(7), campaignPrepare(8)
	// Identical request IDs must not collide across campaigns, even though the
	// operation scope (and consequently the immutable request digest) differs.
	second.RequestID = first.RequestID
	a, b := mustCampaign(t, owners, first), mustCampaign(t, owners, second)
	if a.StateID != "owner/campaign/7" || b.StateID != "owner/campaign/8" {
		t.Fatalf("unexpected campaign state keys: %q %q", a.StateID, b.StateID)
	}
	if bytes.Equal(a.AgentConfig, b.AgentConfig) {
		t.Fatal("campaigns share a native identity")
	}
	beginA, beginB := campaignBegin(a), campaignBegin(b)
	beginB.RequestID = beginA.RequestID
	sa, sb := mustCampaign(t, owners, beginA), mustCampaign(t, owners, beginB)
	if sa.SessionRef == sb.SessionRef {
		t.Fatal("campaign sessions share a reference")
	}
	keyA, keyB := wire.StateKey{Namespace: a.Namespace, StateID: a.StateID}, wire.StateKey{Namespace: b.Namespace, StateID: b.StateID}
	stateA, _ := store.Load(context.Background(), keyA)
	stateB, _ := store.Load(context.Background(), keyB)
	var dataA, dataB ownerData
	if json.Unmarshal(stateA.ProviderJSON, &dataA) != nil || json.Unmarshal(stateB.ProviderJSON, &dataB) != nil {
		t.Fatal("invalid persisted metadata")
	}
	if dataA.OperationID != 7 || dataB.OperationID != 8 || len(dataA.Profiles) != 1 || len(dataB.Profiles) != 1 || len(dataA.Sessions) != 1 || len(dataB.Sessions) != 1 || len(dataA.Requests) != 2 || len(dataB.Requests) != 2 {
		t.Fatalf("campaign metadata is not isolated: %+v %+v", dataA, dataB)
	}
	// Both campaigns independently admit two requests under the configured
	// limit. Exhausting one campaign does not consume another's capacity.
	request := campaignSeal(sa)
	if response := owners.Handle(context.Background(), request); response.Success || response.Error.Code != "capacity" {
		t.Fatalf("expected campaign-local request limit: %+v", response)
	}
	if got := mustCampaign(t, owners, second); got.ProfileRef != b.ProfileRef {
		t.Fatal("campaign retry returned a different result")
	}
	cross := campaignSeal(sa)
	cross.OperationScopeID = 8
	// Preserve A's explicit routing key: rejection happens before B can be
	// acquired or its durable metadata read.
	if response := owners.Handle(context.Background(), cross); response.Success || response.Error.Outcome != wire.OutcomeRejected {
		t.Fatalf("cross-campaign routing accepted: %+v", response)
	}
	cross.StateID, cross.Namespace = b.StateID, b.Namespace
	if response := owners.Handle(context.Background(), cross); response.Success || response.Error.Code != "unavailable_session" {
		t.Fatalf("cross-campaign session accepted: %+v", response)
	}
	if after, _ := store.Load(context.Background(), keyA); after.Revision != stateA.Revision {
		t.Fatal("unrelated campaign changed A's checkpoint")
	}
	if after, _ := store.Load(context.Background(), keyB); after.Revision != stateB.Revision {
		t.Fatal("rejected cross-campaign requests changed B's checkpoint")
	}
}

func TestCampaignsProvisionOnlyForValidPrepare(t *testing.T) {
	store, factory := newCampaignMemoryStore(), &campaignFactory{}
	owners := testCampaigns(t, Config{}, store, factory)
	describe := testRequest(wire.Describe)
	mustCampaign(t, owners, describe)
	if len(owners.owners) != 0 || len(store.rows) != 0 {
		t.Fatal("Describe created a campaign")
	}
	lookup := testRequest(wire.GetOperation)
	lookup.LookupRequestID = uuid.NewString()
	seal := testRequest(wire.Seal)
	seal.SessionRef, seal.Namespace = uuid.NewString(), "beaconcrypt"
	begin := testRequest(wire.BeginSession)
	begin.ProfileRef, begin.PayloadUUID, begin.NextUUID, begin.Message = uuid.NewString(), uuid.NewString(), uuid.NewString(), []byte("registration")
	for _, request := range []wire.Request{lookup, seal, begin} {
		response := owners.Handle(context.Background(), request)
		if response.Success || response.Error.Code != "owner_unavailable" {
			t.Fatalf("missing campaign did not fail closed for %s: %+v", request.Method, response)
		}
	}
	invalid := campaignPrepare(7)
	invalid.ProviderJSON = json.RawMessage(`{"unsupported":true}`)
	if response := owners.Handle(context.Background(), invalid); response.Success || response.Error.Code != "invalid_input" {
		t.Fatalf("unsupported profile accepted: %+v", response)
	}
	explicit := campaignPrepare(7)
	explicit.Namespace, explicit.StateID = "beaconcrypt", "server/campaign/7"
	if response := owners.Handle(context.Background(), explicit); response.Success || response.Error.Code != "owner_unavailable" {
		t.Fatalf("state-routed prepare recreated missing state: %+v", response)
	}
	if factory.created != 0 {
		t.Fatal("nonprovisioning request created a native identity")
	}
	prepared := mustCampaign(t, owners, campaignPrepare(7))
	key := wire.StateKey{Namespace: prepared.Namespace, StateID: prepared.StateID}
	store.row(key).mu.Lock()
	store.row(key).state = nil
	store.row(key).mu.Unlock()
	if response := owners.Handle(context.Background(), campaignPrepare(7)); response.Success {
		t.Fatal("live campaign silently recreated its missing state")
	}
	if response := owners.Handle(context.Background(), campaignPrepare(7)); response.Success {
		t.Fatal("retired campaign silently recreated its missing state")
	}
	if factory.created != 1 {
		t.Fatal("missing established state regenerated an identity")
	}
}

func TestCampaignsBlockedCommitDoesNotBlockOtherCampaign(t *testing.T) {
	store, factory := newCampaignMemoryStore(), &campaignFactory{}
	owners := testCampaigns(t, Config{}, store, factory)
	a := mustCampaign(t, owners, campaignPrepare(7))
	b := mustCampaign(t, owners, campaignPrepare(8))
	sa, sb := mustCampaign(t, owners, campaignBegin(a)), mustCampaign(t, owners, campaignBegin(b))
	requestA, requestB := campaignSeal(sa), campaignSeal(sb)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseCommit := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCommit()
	store.beforeCommit = func(_ context.Context, request wire.CommitStateRequest) {
		if request.RequestID == requestA.RequestID {
			close(entered)
			<-release
		}
	}
	doneA, doneB := make(chan wire.Response, 1), make(chan wire.Response, 1)
	go func() { doneA <- owners.Handle(context.Background(), requestA) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first campaign never reached its durable commit")
	}
	go func() { doneB <- owners.Handle(context.Background(), requestB) }()
	select {
	case response := <-doneB:
		if !response.Success {
			t.Fatalf("other campaign failed while first commit blocked: %+v", response.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("one campaign's storage IO blocked another campaign")
	}
	// Same-campaign work must still wait for the first immutable commit.
	doneSame := make(chan wire.Response, 1)
	go func() { doneSame <- owners.Handle(context.Background(), requestA) }()
	select {
	case <-doneSame:
		t.Fatal("same-campaign retry bypassed its owner mutex")
	case <-time.After(30 * time.Millisecond):
	}
	// The deferred release also handles failure paths above.
	releaseCommit()
	for _, done := range []chan wire.Response{doneA, doneSame} {
		select {
		case response := <-done:
			if !response.Success {
				t.Fatalf("first campaign failed after release: %+v", response.Error)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("first campaign did not finish after release")
		}
	}
}

func TestCampaignsRestoreIndependentOwnersAndFenceOnlyReplacement(t *testing.T) {
	store, factory := newCampaignMemoryStore(), &campaignFactory{}
	first := testCampaigns(t, Config{}, store, factory)
	pa, pb := campaignPrepare(7), campaignPrepare(8)
	a, b := mustCampaign(t, first, pa), mustCampaign(t, first, pb)
	sa, sb := mustCampaign(t, first, campaignBegin(a)), mustCampaign(t, first, campaignBegin(b))
	sendA, sendB := campaignSeal(sa), campaignSeal(sb)
	savedA, savedB := mustCampaign(t, first, sendA), mustCampaign(t, first, sendB)
	second := testCampaigns(t, Config{}, store, factory)
	// Replacing A acquires only A's durable ownership epoch. B stays live in
	// the old worker, while A's exact result and identity survive restoration.
	if result := mustCampaign(t, second, pa); result.ProfileRef != a.ProfileRef || !bytes.Equal(result.AgentConfig, a.AgentConfig) {
		t.Fatal("restored campaign lost its original profile or identity")
	}
	if result := mustCampaign(t, second, sendA); !bytes.Equal(result.Message, savedA.Message) {
		t.Fatal("restored campaign did not recover its exact committed result")
	}
	if response := first.Handle(context.Background(), campaignSeal(sa)); response.Success || response.Error.Code != "stale_owner" {
		t.Fatalf("superseded campaign was not fenced: %+v", response)
	}
	mustCampaign(t, first, campaignSeal(sb))
	first.Close()
	if result := mustCampaign(t, second, pb); result.ProfileRef != b.ProfileRef || !bytes.Equal(result.AgentConfig, b.AgentConfig) {
		t.Fatal("second campaign identity changed across restart")
	}
	if result := mustCampaign(t, second, sendB); !bytes.Equal(result.Message, savedB.Message) {
		t.Fatal("second campaign result lost across restart")
	}
	mustCampaign(t, second, campaignSeal(sb))
	if factory.created != 2 {
		t.Fatalf("restart created replacement identities: %d", factory.created)
	}
	second.Close()
	if response := second.Handle(context.Background(), campaignPrepare(9)); response.Success {
		t.Fatal("closed router accepted a new campaign")
	}
}

func TestCampaignStateKeyPrefixLimits(t *testing.T) {
	reserved := len(campaignStateSuffix) + len("9223372036854775807")
	for _, test := range []struct {
		length int
		valid  bool
	}{{wire.MaxStateIDBytes - reserved, true}, {wire.MaxStateIDBytes - reserved + 1, false}} {
		owners, err := NewCampaigns(Config{StateID: strings.Repeat("a", test.length)}, &campaignFactory{}, newCampaignMemoryStore())
		if (err == nil) != test.valid {
			t.Fatalf("prefix length %d: %v", test.length, err)
		}
		if owners != nil {
			if len(owners.stateID(int(^uint(0)>>1))) > wire.MaxStateIDBytes {
				t.Fatal("largest campaign ID exceeds durable state key limit")
			}
			owners.Close()
		}
	}
	owners := testCampaigns(t, Config{}, newCampaignMemoryStore(), &campaignFactory{})
	if got := owners.stateID(7); !strings.HasSuffix(got, campaignStateSuffix+strconv.Itoa(7)) {
		t.Fatalf("unstable campaign key: %q", got)
	}
}

func TestCampaignsConcurrentFirstProfilesShareOneCampaignIdentity(t *testing.T) {
	store, factory := newCampaignMemoryStore(), &campaignFactory{}
	owners := testCampaigns(t, Config{}, store, factory)
	const profiles = 8
	responses := make(chan wire.Response, profiles)
	for range profiles {
		go func() { responses <- owners.Handle(context.Background(), campaignPrepare(7)) }()
	}
	seen := make(map[string]bool)
	var identity []byte
	for range profiles {
		response := <-responses
		if !response.Success {
			t.Fatalf("concurrent profile creation failed: %+v", response.Error)
		}
		if seen[response.ProfileRef] {
			t.Fatal("concurrent profiles unexpectedly share a profile reference")
		}
		seen[response.ProfileRef] = true
		if identity == nil {
			identity = response.AgentConfig
		} else if !bytes.Equal(identity, response.AgentConfig) {
			t.Fatal("profiles in one campaign have different server identities")
		}
	}
	if factory.created != 1 {
		t.Fatalf("concurrent first builds created %d campaign identities", factory.created)
	}
}

func TestCampaignsRejectPersistedMetadataForAnotherCampaign(t *testing.T) {
	store, factory := newCampaignMemoryStore(), &campaignFactory{}
	first := testCampaigns(t, Config{}, store, factory)
	request := campaignPrepare(7)
	profile := mustCampaign(t, first, request)
	first.Close()
	key := wire.StateKey{Namespace: profile.Namespace, StateID: profile.StateID}
	row := store.row(key)
	row.mu.Lock()
	var data ownerData
	if err := json.Unmarshal(row.state.ProviderJSON, &data); err != nil {
		row.mu.Unlock()
		t.Fatal(err)
	}
	data.OperationID = 8
	row.state.ProviderJSON, _ = json.Marshal(data)
	row.mu.Unlock()
	second := testCampaigns(t, Config{}, store, factory)
	if response := second.Handle(context.Background(), request); response.Success || response.Error.Code != "owner_unavailable" {
		t.Fatalf("campaign accepted another campaign's durable metadata: %+v", response)
	}
	if factory.created != 1 {
		t.Fatal("invalid persisted metadata caused a new identity")
	}
}
