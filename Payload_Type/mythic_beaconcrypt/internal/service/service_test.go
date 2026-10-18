package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/storage"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	sdk "github.com/MythicMeta/MythicContainer/rabbitmq"
	"github.com/google/uuid"
)

type processorFunc func(context.Context, wire.Request) wire.Response

func (f processorFunc) Handle(ctx context.Context, request wire.Request) wire.Response {
	return f(ctx, request)
}

type callerFunc func(context.Context, string, []byte) ([]byte, error)

func (f callerFunc) Call(ctx context.Context, route string, body []byte) ([]byte, error) {
	return f(ctx, route, body)
}

func TestHandlerRejectsMalformedOrMissingAuthorizationBeforeProcessing(t *testing.T) {
	for _, name := range []string{"malformed JSON", "missing header", "missing request context", "mismatched context"} {
		t.Run(name, func(t *testing.T) {
			ctx := sdk.NewContextWithAuthToken(context.Background(), "mctx_current-attempt")
			request := wire.Request{APIVersion: wire.APIVersion, RequestID: uuid.NewString(), OperationScopeID: 17, Method: wire.Describe, AuthContext: "mctx_current-attempt"}
			switch name {
			case "missing header":
				ctx = context.Background()
			case "missing request context":
				request.AuthContext = ""
			case "mismatched context":
				request.AuthContext = "mctx_other-attempt"
			}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if name == "malformed JSON" {
				body = []byte("{")
			}
			calls := 0
			handler := NewHandler(processorFunc(func(context.Context, wire.Request) wire.Response { calls++; return wire.Response{} }), time.Second)
			body, err = handler(ctx, body)
			if err != nil || !json.Valid(body) || calls != 0 {
				t.Fatalf("invalid input reached processor or stopped consumer: calls=%d response=%q err=%v", calls, body, err)
			}
			var result struct {
				Success bool `json:"success"`
			}
			if err := json.Unmarshal(body, &result); err != nil || result.Success {
				t.Fatalf("invalid input was accepted: %s %v", body, err)
			}
		})
	}
}

func TestHandlerPreservesRequestScopeAndAuthorization(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "failure"}[success], func(t *testing.T) {
			request := wire.Request{APIVersion: wire.APIVersion, RequestID: uuid.NewString(), OperationScopeID: 17, Method: wire.Describe, AuthContext: "mctx_transient-attempt"}
			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			handler := NewHandler(processorFunc(func(ctx context.Context, got wire.Request) wire.Response {
				calls++
				if !reflect.DeepEqual(got, request) {
					t.Fatalf("request changed: %#v", got)
				}
				if token, ok := sdk.AuthTokenFromContext(ctx); !ok || token != request.AuthContext {
					t.Fatal("processor lost transient SDK authorization")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > time.Second {
					t.Fatal("processor did not receive bounded request context")
				}
				response := wire.Response{APIVersion: wire.APIVersion, RequestID: got.RequestID, OperationScopeID: got.OperationScopeID, AuthContext: got.AuthContext, Success: success}
				if success {
					response.ProviderJSON = json.RawMessage(`{"provider":"example"}`)
				} else {
					response.Error = &wire.Failure{Code: "invalid_input", Message: "request rejected", Outcome: wire.OutcomeRejected}
				}
				return response
			}), time.Second)
			ctx := sdk.NewContextWithAuthToken(context.Background(), request.AuthContext)
			body, err := handler(ctx, payload)
			if err != nil {
				t.Fatal(err)
			}
			var response wire.Response
			if err = json.Unmarshal(body, &response); err != nil {
				t.Fatal(err)
			}
			if response.RequestID != request.RequestID || response.OperationScopeID != request.OperationScopeID || response.AuthContext != request.AuthContext || response.Success != success || calls != 1 {
				t.Fatalf("response correlation changed: %#v, calls=%d", response, calls)
			}
			err = response.Validate(request)
			if success && err != nil {
				t.Fatal(err)
			}
			if !success {
				var failure *wire.Failure
				if !errors.As(err, &failure) || failure.Code != "invalid_input" || failure.Outcome != wire.OutcomeRejected {
					t.Fatalf("failure was not preserved: %v", err)
				}
			}
		})
	}
}

func TestSyncUsesV4ContainerWireAndConfiguredMetadata(t *testing.T) {
	config := Config{Name: "custom-provider", Description: "Example provider", Version: "2.3.4", RPCTimeout: time.Second, Capabilities: wire.Capabilities{APIVersion: wire.APIVersion, Schemes: []string{"example", "other"}, Establishment: "single_round", SessionPersistence: "volatile", MaxMessageBytes: 12345, ResultRetentionSeconds: 67890}}
	calls := 0
	caller := callerFunc(func(ctx context.Context, route string, body []byte) ([]byte, error) {
		calls++
		if route != SyncRoute {
			t.Fatalf("wrong sync route: %q", route)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("sync has no deadline")
		}
		var message struct {
			ContainerVersion string `json:"container_version"`
			Container        struct {
				Name          string            `json:"name"`
				Type          string            `json:"type"`
				SemVer        string            `json:"semver"`
				Description   string            `json:"description"`
				Subscriptions []string          `json:"subscriptions"`
				Capabilities  wire.Capabilities `json:"crypto_capabilities"`
			} `json:"consuming_container"`
		}
		if err := json.Unmarshal(body, &message); err != nil {
			t.Fatal(err)
		}
		if message.ContainerVersion != "v1.5.0" || message.Container.Name != config.Name || message.Container.Type != "crypto" || message.Container.SemVer != config.Version || message.Container.Description != config.Description || message.Container.Subscriptions == nil || len(message.Container.Subscriptions) != 0 {
			t.Fatalf("invalid consuming-container sync: %s", body)
		}
		if !reflect.DeepEqual(message.Container.Capabilities, config.Capabilities) {
			t.Fatalf("advertised capabilities differ from config: %#v vs %#v", message.Container.Capabilities, config.Capabilities)
		}
		if err := message.Container.Capabilities.Validate(); err != nil {
			t.Fatal(err)
		}
		return []byte(`{"success":true}`), nil
	})
	if err := Sync(context.Background(), caller, config); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("sync repeated %d times", calls)
	}
}

func TestSyncRejectsFailureWithoutRetry(t *testing.T) {
	for _, reply := range []string{`{"success":false,"error":"unsupported container"}`, `not JSON`, `{}`} {
		calls := 0
		err := Sync(context.Background(), callerFunc(func(context.Context, string, []byte) ([]byte, error) { calls++; return []byte(reply), nil }), Config{Name: "example", RPCTimeout: time.Second, Capabilities: wire.Capabilities{APIVersion: wire.APIVersion, Schemes: []string{"example"}, Establishment: "single_round", SessionPersistence: "volatile", MaxMessageBytes: 1024, ResultRetentionSeconds: 60}})
		if err == nil || calls != 1 {
			t.Fatalf("failed sync accepted or repeated: %v calls=%d", err, calls)
		}
	}
}

func TestSyncRejectsInvalidAdvertisementBeforePublishing(t *testing.T) {
	valid := Config{Name: "example", RPCTimeout: time.Second, Capabilities: wire.Capabilities{APIVersion: wire.APIVersion, Schemes: []string{"example"}, Establishment: "single_round", SessionPersistence: "volatile", MaxMessageBytes: 1024, ResultRetentionSeconds: 60}}
	for _, change := range []func(*Config){
		func(config *Config) { config.Name = "bad:name" },
		func(config *Config) { config.Capabilities.APIVersion = 0 },
		func(config *Config) { config.Capabilities.SessionPersistence = "unknown" },
	} {
		config := valid
		change(&config)
		calls := 0
		err := Sync(context.Background(), callerFunc(func(context.Context, string, []byte) ([]byte, error) { calls++; return []byte(`{"success":true}`), nil }), config)
		if err == nil || calls != 0 {
			t.Fatalf("invalid advertisement reached Mythic: error=%v calls=%d", err, calls)
		}
	}
}

func TestRunRejectsInvalidCompositionBeforeConnecting(t *testing.T) {
	if err := Run(context.Background(), Config{}, nil); err == nil {
		t.Fatal("missing backend factory accepted")
	}
	called := false
	err := Run(context.Background(), Config{Name: "example"}, func(storage.Store) (Backend, error) { called = true; return nil, nil })
	if err == nil || called {
		t.Fatalf("invalid capabilities reached backend factory: error=%v called=%v", err, called)
	}
}
