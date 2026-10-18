package provider

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/service"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	"github.com/google/uuid"
)

func testProvider(t *testing.T) (service.Backend, wire.Capabilities) {
	t.Helper()
	t.Setenv("RABBITMQ_URL", "amqp://test:password@127.0.0.1:5672/mythic_vhost")
	t.Setenv("BEACONCRYPT_PROVIDER_NAME", "")
	t.Setenv("BEACONCRYPT_RPC_TIMEOUT", "")
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	// A volatile implementation need not use the optional durable state store.
	backend, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Close)
	return backend, config.Service.Capabilities
}

func requestFor(method string) wire.Request {
	return wire.Request{
		APIVersion: wire.APIVersion, RequestID: uuid.NewString(), OperationScopeID: 7,
		Method: method, Scheme: "example", ProfileRef: "profile", SessionRef: "session",
		Namespace: "operation-7", StateID: "state", Message: []byte("initial-message"),
		PayloadUUID: uuid.NewString(), NextUUID: uuid.NewString(),
		LookupRequestID: uuid.NewString(), AuthContext: "mctx_this-request-only",
	}
}

func assertIdentity(t *testing.T, request wire.Request, response wire.Response) {
	t.Helper()
	if response.APIVersion != wire.APIVersion || response.RequestID != request.RequestID || response.OperationScopeID != request.OperationScopeID || response.AuthContext != request.AuthContext {
		t.Fatal("provider lost API version, request identity, operation scope, or transient authorization")
	}
}

func TestDescribeReportsConfiguredCapabilities(t *testing.T) {
	backend, want := testProvider(t)
	request := requestFor(wire.Describe)
	response := backend.Handle(context.Background(), request)
	assertIdentity(t, request, response)
	if err := response.Validate(request); err != nil {
		t.Fatal(err)
	}
	var got wire.Capabilities
	if err := json.Unmarshal(response.ProviderJSON, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) || got.SessionPersistence != "volatile" {
		t.Fatalf("unexpected capabilities: %#v", got)
	}
}

func TestProtocolStubsRejectBeforeAnyCryptographicEffect(t *testing.T) {
	backend, _ := testProvider(t)
	for _, method := range []string{wire.PrepareProfile, wire.BeginSession, wire.Open, wire.Seal, wire.GetOperation, wire.RevokeSession} {
		t.Run(method, func(t *testing.T) {
			request := requestFor(method)
			if err := request.Validate(); err != nil {
				t.Fatal(err)
			}
			response := backend.Handle(context.Background(), request)
			assertIdentity(t, request, response)
			if response.Success || response.Error == nil || response.Error.Code != "not_implemented" || response.Error.Outcome != wire.OutcomeRejected {
				t.Fatalf("stub was accepted or reported an ambiguous effect: %#v", response)
			}
			if response.ProfileRef != "" || response.SessionRef != "" || len(response.Message) != 0 || len(response.AgentConfig) != 0 {
				t.Fatal("stub manufactured protocol output")
			}
		})
	}
}

func TestInvalidRequestsAreRejectedBeforeDispatch(t *testing.T) {
	backend, _ := testProvider(t)
	for _, change := range []func(*wire.Request){
		func(r *wire.Request) { r.APIVersion++ },
		func(r *wire.Request) { r.RequestID = "invalid" },
		func(r *wire.Request) { r.OperationScopeID = 0 },
		func(r *wire.Request) { r.Method = "unknown" },
	} {
		request := requestFor(wire.Describe)
		change(&request)
		response := backend.Handle(context.Background(), request)
		assertIdentity(t, request, response)
		if response.Success || response.Error == nil || response.Error.Code != "invalid_input" || response.Error.Outcome != wire.OutcomeRejected {
			t.Fatalf("invalid input was accepted: %#v", response)
		}
	}
}
