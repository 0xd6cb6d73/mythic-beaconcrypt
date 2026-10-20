package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
)

func TestCapabilitiesAdvertiseBackendAliasesWithoutSharingSlices(t *testing.T) {
	owners := testCampaigns(t, Config{}, newCampaignMemoryStore(), &campaignFactory{})
	want := []string{"beaconcrypt", "Native", "WASM"}
	for _, capabilities := range []wire.Capabilities{owners.Capabilities(), (&Engine{config: owners.config}).Capabilities()} {
		if err := capabilities.Validate(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(capabilities.Schemes, want) {
			t.Fatalf("schemes=%v", capabilities.Schemes)
		}
		for _, scheme := range want {
			if !capabilities.Supports(scheme) {
				t.Fatalf("missing %s", scheme)
			}
		}
		capabilities.Schemes[0] = "changed"
	}
	if !reflect.DeepEqual(owners.Capabilities().Schemes, want) {
		t.Fatal("caller changed advertised schemes")
	}
	request := testRequest(wire.Describe)
	response := mustCampaign(t, owners, request)
	var described wire.Capabilities
	if err := json.Unmarshal(response.ProviderJSON, &described); err != nil || !reflect.DeepEqual(described.Schemes, want) {
		t.Fatalf("describe=%s err=%v", response.ProviderJSON, err)
	}
	for _, scheme := range []string{"native", "wasm", "other"} {
		request := campaignPrepare(7)
		request.Scheme = scheme
		requireFailure(t, owners.Handle(context.Background(), request), "invalid_input", "rejected")
	}
	if len(owners.owners) != 0 {
		t.Fatal("unsupported scheme provisioned a campaign")
	}
}

func TestCampaignBackendAliasesShareIdentityAndKeepExactRequestDigests(t *testing.T) {
	ctx := context.Background()
	store, factory := newCampaignMemoryStore(), &campaignFactory{}
	owners := testCampaigns(t, Config{}, store, factory)
	var identity []byte
	var stateKey wire.StateKey
	var retained []struct {
		request  wire.Request
		response wire.Response
	}
	for i, scheme := range []string{Scheme, SchemeNative, SchemeWASM} {
		t.Run(scheme, func(t *testing.T) {
			prepare := campaignPrepare(7)
			prepare.Scheme = scheme
			profile := mustCampaign(t, owners, prepare)
			key := wire.StateKey{Namespace: profile.Namespace, StateID: profile.StateID}
			if identity == nil {
				identity, stateKey = bytes.Clone(profile.AgentConfig), key
			}
			if !bytes.Equal(identity, profile.AgentConfig) || key != stateKey || factory.created != 1 {
				t.Fatal("alias created a separate campaign identity or owner")
			}
			checkAliasRetry := func(request wire.Request, original wire.Response) {
				t.Helper()
				before, err := store.Load(ctx, key)
				if err != nil {
					t.Fatal(err)
				}
				digest, err := request.Digest()
				if err != nil {
					t.Fatal(err)
				}
				retained, err := store.LookupResult(ctx, wire.LookupResultRequest{StateKey: key, RequestID: request.RequestID, InputDigest: digest})
				if err != nil || retained.InputDigest != digest {
					t.Fatalf("original scheme digest was not retained: %v", err)
				}
				changed := request
				changed.Scheme = SchemeNative
				if changed.Scheme == request.Scheme {
					changed.Scheme = SchemeWASM
				}
				requireFailure(t, owners.Handle(ctx, changed), "request_conflict", "rejected")
				replay := mustCampaign(t, owners, request)
				if !reflect.DeepEqual(replay, original) {
					t.Fatal("exact alias retry changed its retained result")
				}
				after, err := store.Load(ctx, key)
				if err != nil || before.Revision != after.Revision || !bytes.Equal(before.StateBlob, after.StateBlob) || !bytes.Equal(before.ProviderJSON, after.ProviderJSON) {
					t.Fatal("alias conflict or retry mutated durable state")
				}
			}
			checkAliasRetry(prepare, profile)
			begin := campaignBegin(profile)
			begin.Scheme = scheme
			session := mustCampaign(t, owners, begin)
			checkAliasRetry(begin, session)
			open := sessionRequest(wire.Open, profile, session, []byte(fmt.Sprintf("%d|authenticated plaintext", 11+i)))
			open.Scheme = scheme
			opened := mustCampaign(t, owners, open)
			if string(opened.Message) != "authenticated plaintext" {
				t.Fatal("open lost plaintext")
			}
			checkAliasRetry(open, opened)
			seal := sessionRequest(wire.Seal, profile, session, []byte("server plaintext"))
			seal.Scheme = scheme
			sealed := mustCampaign(t, owners, seal)
			if !bytes.HasSuffix(sealed.Message, []byte(":server plaintext")) {
				t.Fatal("seal lost plaintext")
			}
			checkAliasRetry(seal, sealed)
			retained = append(retained, struct {
				request  wire.Request
				response wire.Response
			}{seal, sealed})
		})
	}
	owners.Close()
	recovered := testCampaigns(t, Config{}, store, factory)
	for _, saved := range retained {
		request := saved.request
		changed := request
		changed.Scheme = SchemeWASM
		if changed.Scheme == request.Scheme {
			changed.Scheme = SchemeNative
		}
		requireFailure(t, recovered.Handle(ctx, changed), "request_conflict", "rejected")
		if replay := mustCampaign(t, recovered, request); !reflect.DeepEqual(replay, saved.response) {
			t.Fatal("restored owner changed retained alias result")
		}
		lookup := testRequest(wire.GetOperation)
		lookup.Scheme, lookup.LookupRequestID = request.Scheme, request.RequestID
		if result := mustCampaign(t, recovered, lookup); !bytes.Equal(result.Message, saved.response.Message) {
			t.Fatal("alias lookup lost the retained result")
		}
	}
	if factory.created != 1 {
		t.Fatal("recovery created a new campaign identity")
	}
}
