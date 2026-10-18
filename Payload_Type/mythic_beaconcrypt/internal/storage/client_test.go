package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	sdk "github.com/MythicMeta/MythicContainer/rabbitmq"
)

type callerFunc func(context.Context, string, []byte) ([]byte, error)

func (f callerFunc) Call(ctx context.Context, route string, body []byte) ([]byte, error) {
	return f(ctx, route, body)
}

func responseBytes(t *testing.T, response response) []byte {
	t.Helper()
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func decodeRequest(t *testing.T, route string, body []byte) request {
	t.Helper()
	if route != Route {
		t.Fatalf("wrong storage route: %q", route)
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	if req.APIVersion != wire.APIVersion || req.RequestID == "" || req.ProviderName != "beaconcrypt" {
		t.Fatalf("invalid storage request: %#v", req)
	}
	return req
}

func newTestClient(t *testing.T, call callerFunc) *Client {
	t.Helper()
	client, err := New(call, "beaconcrypt")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestStorageClientTypedMethodsAndBinaryState(t *testing.T) {
	key := wire.StateKey{Namespace: "server", StateID: "owner-1"}
	blob := []byte{0, 255, 128, 1, 0}
	digest := strings.Repeat("a", 64)
	seen := map[string]bool{}
	client := newTestClient(t, func(_ context.Context, route string, body []byte) ([]byte, error) {
		req := decodeRequest(t, route, body)
		if seen[req.RequestID] {
			t.Fatal("outer storage request ID was reused")
		}
		seen[req.RequestID] = true
		var result any
		switch req.Method {
		case "load", "create":
			result = wire.StoredState{StateKey: key, StateBlob: blob, ProviderJSON: json.RawMessage(`{}`)}
		case "acquire":
			var input wire.AcquireStateRequest
			if err := json.Unmarshal(req.Input, &input); err != nil {
				t.Fatal(err)
			}
			if input.ExpectedOwnerEpoch != 0 {
				t.Fatal("wrong expected epoch")
			}
			result = wire.StoredState{StateKey: key, StateBlob: blob, ProviderJSON: json.RawMessage(`{}`), OwnerEpoch: 1}
		case "commit":
			var input wire.CommitStateRequest
			if err := json.Unmarshal(req.Input, &input); err != nil {
				t.Fatal(err)
			}
			if string(input.StateBlob) != string(blob) || input.RequestID != "immutable-id" || input.InputDigest != digest {
				t.Fatal("commit input changed")
			}
			result = wire.CommitResult{Revision: 1, Result: json.RawMessage(`{"message":"AP8="}`)}
		case "get_result":
			result = wire.OperationResult{StateKey: key, RequestID: "immutable-id", InputDigest: digest, Revision: 1, Result: json.RawMessage(`{"message":"AP8="}`)}
		default:
			t.Fatalf("unexpected method %q", req.Method)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		return responseBytes(t, response{APIVersion: wire.APIVersion, RequestID: req.RequestID, ProviderName: req.ProviderName, Success: true, Result: encoded}), nil
	})
	loaded, err := client.Load(context.Background(), key)
	if err != nil || string(loaded.StateBlob) != string(blob) {
		t.Fatalf("load: %#v %v", loaded, err)
	}
	if _, err = client.Create(context.Background(), wire.CreateStateRequest{StateKey: key, StateBlob: blob}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Acquire(context.Background(), wire.AcquireStateRequest{StateKey: key}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Commit(context.Background(), wire.CommitStateRequest{StateKey: key, RequestID: "immutable-id", InputDigest: digest, StateBlob: blob}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.LookupResult(context.Background(), wire.LookupResultRequest{StateKey: key, RequestID: "immutable-id", InputDigest: digest}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 5 {
		t.Fatalf("expected five calls, got %d", len(seen))
	}
}

func TestStorageClientRejectsMalformedOrMismatchedReplies(t *testing.T) {
	for _, name := range []string{"missing correlation", "malformed JSON", "request id", "provider name", "api version", "contradiction", "missing result", "wrong state"} {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, func(_ context.Context, route string, body []byte) ([]byte, error) {
				req := decodeRequest(t, route, body)
				res := response{APIVersion: wire.APIVersion, RequestID: req.RequestID, ProviderName: req.ProviderName, Success: true, Result: json.RawMessage(`{"namespace":"server","state_id":"owner-1","state_blob":"AA==","provider_json":{},"revision":0,"owner_epoch":0}`)}
				switch name {
				case "missing correlation":
					return []byte(`{"success":false,"error":"unauthorized"}`), nil
				case "request id":
					res.RequestID = "another-request"
				case "provider name":
					res.ProviderName = "another-provider"
				case "api version":
					res.APIVersion++
				case "contradiction":
					res.Error = &wire.Failure{Code: "not_found"}
				case "missing result":
					res.Result = nil
				case "wrong state":
					res.Result = json.RawMessage(`{"namespace":"other","state_id":"owner-1","state_blob":"AA==","provider_json":{}}`)
				}
				reply := responseBytes(t, res)
				if name == "malformed JSON" {
					reply = []byte("{")
				}
				return reply, nil
			})
			if _, err := client.Load(context.Background(), wire.StateKey{Namespace: "server", StateID: "owner-1"}); err == nil {
				t.Fatal("accepted invalid reply")
			}
		})
	}
}

func TestStorageClientMapsCorrelatedFailures(t *testing.T) {
	for code, sentinel := range map[string]error{"not_found": wire.ErrNotFound, "already_exists": wire.ErrAlreadyExists, "stale_writer": wire.ErrStaleWriter, "request_conflict": wire.ErrRequestConflict, "invalid_input": wire.ErrInvalidInput} {
		t.Run(code, func(t *testing.T) {
			client := newTestClient(t, func(_ context.Context, route string, body []byte) ([]byte, error) {
				req := decodeRequest(t, route, body)
				return responseBytes(t, response{APIVersion: wire.APIVersion, RequestID: req.RequestID, ProviderName: req.ProviderName, Error: &wire.Failure{Code: code, Message: "trusted failure"}}), nil
			})
			if _, err := client.Load(context.Background(), wire.StateKey{}); !errors.Is(err, sentinel) {
				t.Fatalf("wrong error: %v", err)
			}
		})
	}
}

func TestStorageClientNeverAutomaticallyRetriesUncertainCommit(t *testing.T) {
	calls := 0
	lost := errors.New("response lost after commit")
	client := newTestClient(t, func(context.Context, string, []byte) ([]byte, error) { calls++; return nil, lost })
	_, err := client.Commit(context.Background(), wire.CommitStateRequest{})
	if calls != 1 || !errors.Is(err, lost) || errors.Is(err, wire.ErrNotFound) {
		t.Fatalf("uncertain commit was trusted or retried: %d %v", calls, err)
	}
}

func TestStorageClientForwardsTransientSDKAuthorization(t *testing.T) {
	const token = "mctx_campaign-request"
	client := newTestClient(t, func(ctx context.Context, route string, body []byte) ([]byte, error) {
		if got, ok := sdk.AuthTokenFromContext(ctx); !ok || got != token {
			t.Fatal("storage call lost caller authorization context")
		}
		if strings.Contains(string(body), token) {
			t.Fatal("storage body retained transient authorization")
		}
		req := decodeRequest(t, route, body)
		return responseBytes(t, response{APIVersion: wire.APIVersion, RequestID: req.RequestID, ProviderName: req.ProviderName, Error: &wire.Failure{Code: "not_found"}}), nil
	})
	_, err := client.Load(sdk.NewContextWithAuthToken(context.Background(), token), wire.StateKey{})
	if !errors.Is(err, wire.ErrNotFound) {
		t.Fatalf("unexpected storage failure: %v", err)
	}
}
