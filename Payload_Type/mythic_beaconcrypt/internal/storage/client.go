// Package storage is the authenticated client for Mythic's generic opaque
// provider store. It never imports the Mythic server or opens its database.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/transport"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	"github.com/google/uuid"
)

const Route = "mythic_rpc_crypto_provider_storage"

type Store interface {
	Load(context.Context, wire.StateKey) (wire.StoredState, error)
	Create(context.Context, wire.CreateStateRequest) (wire.StoredState, error)
	Acquire(context.Context, wire.AcquireStateRequest) (wire.StoredState, error)
	Commit(context.Context, wire.CommitStateRequest) (wire.CommitResult, error)
	LookupResult(context.Context, wire.LookupResultRequest) (wire.OperationResult, error)
}

type Client struct {
	caller transport.Caller
	name   string
}

func New(caller transport.Caller, name string) (*Client, error) {
	if caller == nil || name == "" {
		return nil, errors.New("invalid crypto storage client configuration")
	}
	if _, err := wire.RoutingKey(name); err != nil {
		return nil, err
	}
	return &Client{caller: caller, name: name}, nil
}

type request struct {
	APIVersion   int             `json:"api_version"`
	RequestID    string          `json:"request_id"`
	ProviderName string          `json:"provider_name"`
	Method       string          `json:"method"`
	Input        json.RawMessage `json:"input"`
}

type response struct {
	APIVersion   int             `json:"api_version"`
	RequestID    string          `json:"request_id"`
	ProviderName string          `json:"provider_name"`
	Success      bool            `json:"success"`
	Result       json.RawMessage `json:"result,omitempty"`
	Error        *wire.Failure   `json:"error,omitempty"`
}

// Call invokes the SDK with a fresh RPC request ID and the caller's transient
// Mythic authorization context. Publish retries use the same JSON bytes; the
// SDK does not retry a response timeout. The immutable commit/get_result input
// ID is independent of this ID. Mismatched, malformed, or lost replies remain
// uncertain outcomes rather than trusted storage failures.
func (c *Client) call(ctx context.Context, method string, input, output any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode crypto storage input: %w", err)
	}
	req := request{APIVersion: wire.APIVersion, RequestID: uuid.NewString(), ProviderName: c.name, Method: method, Input: data}
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	reply, err := c.caller.Call(ctx, Route, payload)
	if err != nil {
		return fmt.Errorf("crypto storage %s outcome is uncertain: %w", method, err)
	}
	if len(reply) > transport.MaxBodyBytes {
		return errors.New("crypto storage response exceeds limit")
	}
	var result response
	if err := json.Unmarshal(reply, &result); err != nil {
		return fmt.Errorf("invalid crypto storage response: %w", err)
	}
	if result.APIVersion != wire.APIVersion || result.RequestID != req.RequestID || result.ProviderName != c.name {
		return errors.New("mismatched crypto storage response")
	}
	if !result.Success {
		if result.Error == nil || result.Error.Code == "" || len(result.Result) != 0 {
			return errors.New("invalid crypto storage failure")
		}
		return storageError(result.Error)
	}
	if result.Error != nil || len(result.Result) == 0 || string(result.Result) == "null" {
		return errors.New("invalid crypto storage success")
	}
	if err := json.Unmarshal(result.Result, output); err != nil {
		return fmt.Errorf("decode crypto storage result: %w", err)
	}
	return nil
}

func storageError(failure *wire.Failure) error {
	var sentinel error
	switch failure.Code {
	case "invalid_input":
		sentinel = wire.ErrInvalidInput
	case "not_found":
		sentinel = wire.ErrNotFound
	case "already_exists":
		sentinel = wire.ErrAlreadyExists
	case "stale_writer":
		sentinel = wire.ErrStaleWriter
	case "request_conflict":
		sentinel = wire.ErrRequestConflict
	}
	if sentinel != nil {
		return fmt.Errorf("%w: %s", sentinel, failure.Message)
	}
	return failure
}

func (c *Client) Load(ctx context.Context, input wire.StateKey) (wire.StoredState, error) {
	var output wire.StoredState
	err := c.call(ctx, "load", input, &output)
	if err == nil {
		err = validateState(input, output)
	}
	return output, err
}

func (c *Client) Create(ctx context.Context, input wire.CreateStateRequest) (wire.StoredState, error) {
	var output wire.StoredState
	err := c.call(ctx, "create", input, &output)
	if err == nil {
		err = validateState(input.StateKey, output)
	}
	return output, err
}

func (c *Client) Acquire(ctx context.Context, input wire.AcquireStateRequest) (wire.StoredState, error) {
	var output wire.StoredState
	err := c.call(ctx, "acquire", input, &output)
	if err == nil {
		err = validateState(input.StateKey, output)
		if err == nil && output.OwnerEpoch != input.ExpectedOwnerEpoch+1 {
			err = errors.New("invalid crypto storage owner epoch")
		}
	}
	return output, err
}

func (c *Client) Commit(ctx context.Context, input wire.CommitStateRequest) (wire.CommitResult, error) {
	var output wire.CommitResult
	err := c.call(ctx, "commit", input, &output)
	if err == nil && (output.Revision < 1 || len(output.Result) == 0 || len(output.Result) > wire.MaxResultBytes || !json.Valid(output.Result) || (!output.Cached && output.Revision != input.ExpectedRevision+1)) {
		err = errors.New("invalid crypto storage commit result")
	}
	return output, err
}

func (c *Client) LookupResult(ctx context.Context, input wire.LookupResultRequest) (wire.OperationResult, error) {
	var output wire.OperationResult
	err := c.call(ctx, "get_result", input, &output)
	if err == nil && (output.StateKey != input.StateKey || output.RequestID != input.RequestID || output.InputDigest != input.InputDigest || output.Revision < 1 || len(output.Result) == 0 || len(output.Result) > wire.MaxResultBytes || !json.Valid(output.Result)) {
		err = errors.New("mismatched crypto storage operation result")
	}
	return output, err
}

func validateState(key wire.StateKey, state wire.StoredState) error {
	if state.StateKey != key || state.Revision < 0 || state.OwnerEpoch < 0 || len(state.StateBlob) > wire.MaxStateBlobBytes || len(state.ProviderJSON) > wire.MaxProviderJSONBytes || !json.Valid(state.ProviderJSON) {
		return errors.New("invalid crypto storage state")
	}
	return nil
}
