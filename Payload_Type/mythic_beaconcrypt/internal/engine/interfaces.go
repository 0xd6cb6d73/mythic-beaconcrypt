// Package engine composes Beaconcrypt sessions with Mythic's opaque storage API.
// It has no cgo or transport dependency so durability can be tested independently.
package engine

import (
	"context"
	"errors"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
)

// ErrNativePersistence marks a native persistence outcome as unresolved, even
// when the checkpoint bytes appear unchanged. The owner must be retired.
var ErrNativePersistence = errors.New("native persistence failure")

type Registration struct {
	Data  []byte
	KeyID uint64
}

type Update struct {
	Data  []byte
	KeyID uint64
	Seq   uint64
}

type Native interface {
	IdentityPK() ([]byte, error)
	Register(registration, initial []byte) (Registration, error)
	Encrypt(keyID uint64, plaintext []byte) (Update, error)
	Decrypt(ciphertext []byte) (Update, error)
	Export() ([]byte, error)
	Close()
}

// Factory implementations used by Campaigns must support concurrent calls.
// Returned Native handles belong to individual owners and are serialized there.
type Factory interface {
	New(serverKID uint64) (Native, error)
	Restore(checkpoint []byte) (Native, error)
	SenderKeyID(ciphertext []byte) (uint64, error)
}

type Store interface {
	Load(context.Context, wire.StateKey) (wire.StoredState, error)
	Create(context.Context, wire.CreateStateRequest) (wire.StoredState, error)
	Acquire(context.Context, wire.AcquireStateRequest) (wire.StoredState, error)
	Commit(context.Context, wire.CommitStateRequest) (wire.CommitResult, error)
	LookupResult(context.Context, wire.LookupResultRequest) (wire.OperationResult, error)
}

type Config struct {
	Namespace              string
	StateID                string
	Initialize             bool
	ServerKID              uint64
	MaxProfiles            int
	MaxSessions            int
	MaxRequests            int
	MaxMessageBytes        int
	ResultRetentionSeconds int
}
