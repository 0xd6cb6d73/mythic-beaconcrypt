// Contract adapted from Mythic crypto-provider API v1 at af938ada.
// Keep JSON fields and validation compatible with the Mythic-owned contract.

package wire

import (
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrInvalidInput    = errors.New("invalid crypto provider state request")
	ErrNotFound        = errors.New("crypto provider state or result not found")
	ErrAlreadyExists   = errors.New("crypto provider state already exists")
	ErrStaleWriter     = errors.New("crypto provider owner or revision is stale")
	ErrRequestConflict = errors.New("crypto provider request ID has a different input digest")
)

const (
	MaxNamespaceBytes    = 128
	MaxStateIDBytes      = 256
	MaxRequestIDBytes    = 128
	MaxStateBlobBytes    = 16 << 20
	MaxProviderJSONBytes = 1 << 20
	// Results include base64-encoded message bytes and the provider reply JSON.
	MaxResultBytes = 64 << 20
)

// StateKey identifies one provider-owned state object. The authenticated provider
// ID is always a separate method argument, never supplied by this object.
type StateKey struct {
	Namespace string `json:"namespace" db:"namespace"`
	StateID   string `json:"state_id" db:"state_id"`
}

type StoredState struct {
	StateKey
	StateBlob    []byte          `json:"state_blob" db:"state_blob"`
	ProviderJSON json.RawMessage `json:"provider_json" db:"provider_json"`
	Revision     int64           `json:"revision" db:"revision"`
	OwnerEpoch   int64           `json:"owner_epoch" db:"owner_epoch"`
	UpdatedAt    time.Time       `json:"updated_at" db:"updated_at"`
}

type CreateStateRequest struct {
	StateKey
	StateBlob    []byte          `json:"state_blob"`
	ProviderJSON json.RawMessage `json:"provider_json"`
}

// Acquire is a compare-and-swap on the current epoch, not an unconditional
// increment. Retrying the old expected epoch returns ErrStaleWriter; it cannot
// accidentally fence the successful owner a second time.
type AcquireStateRequest struct {
	StateKey
	ExpectedOwnerEpoch int64 `json:"expected_owner_epoch"`
}

type CommitStateRequest struct {
	StateKey
	ExpectedRevision int64           `json:"expected_revision"`
	OwnerEpoch       int64           `json:"owner_epoch"`
	RequestID        string          `json:"request_id"`
	InputDigest      string          `json:"input_digest"`
	StateBlob        []byte          `json:"state_blob"`
	ProviderJSON     json.RawMessage `json:"provider_json"`
	Result           json.RawMessage `json:"result"`
}

type LookupResultRequest struct {
	StateKey
	RequestID   string `json:"request_id"`
	InputDigest string `json:"input_digest"`
}

type OperationResult struct {
	StateKey
	RequestID   string          `json:"request_id" db:"request_id"`
	InputDigest string          `json:"input_digest" db:"input_digest"`
	Result      json.RawMessage `json:"result" db:"result"`
	Revision    int64           `json:"revision" db:"revision"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
}

type CommitResult struct {
	Revision int64           `json:"revision"`
	Result   json.RawMessage `json:"result"`
	Cached   bool            `json:"cached"`
}
