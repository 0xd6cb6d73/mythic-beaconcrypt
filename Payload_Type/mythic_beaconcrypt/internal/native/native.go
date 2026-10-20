// Package native adapts the pinned Beaconcrypt Go binding without changing its
// protocol. The engine owns serialization and durable checkpoint publication.
package native

import (
	"errors"
	"fmt"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/engine"
)

const (
	UpstreamCommit  = "0c629b1c0af4139b77551da30d39e18b0e77698d"
	UpstreamVersion = "0.6.1"
)

type Factory struct{}

var _ engine.Factory = Factory{}
var _ engine.Native = (*server)(nil)

func (Factory) New(serverKID uint64) (engine.Native, error) {
	handle, err := beaconcrypt.NewServer(serverKID)
	if err != nil {
		return nil, err
	}
	return checkedServer(handle, nil)
}

func (Factory) Restore(checkpoint []byte) (engine.Native, error) {
	previous, err := beaconcrypt.ParseSnapshotHead(checkpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid Beaconcrypt v2 checkpoint: %w", err)
	}
	handle, err := beaconcrypt.NewServerFromState(checkpoint)
	if err != nil {
		return nil, err
	}
	return checkedServer(handle, &previous)
}

// The compatibility constructors keep native transitions private until the
// engine atomically publishes snapshot, metadata, and exact response in Mythic.
// A caller-store CAS cannot include an output that native code has not returned.
func checkedServer(handle *beaconcrypt.Server, expected *beaconcrypt.SnapshotHead) (engine.Native, error) {
	checkpoint, err := handle.ExportState()
	if err == nil {
		_, err = beaconcrypt.ValidateSnapshotSuccessor(checkpoint, expected)
	}
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("invalid Beaconcrypt activation checkpoint: %w", err)
	}
	return &server{handle: handle}, nil
}

// Typed persistence failures are never downgraded to ordinary rejection just
// because a subsequent export happens to match the previous checkpoint.
func mutationError(err error) error {
	var persistence *beaconcrypt.PersistenceError
	if errors.As(err, &persistence) {
		return fmt.Errorf("%w: %w", engine.ErrNativePersistence, err)
	}
	return err
}

func (Factory) SenderKeyID(ciphertext []byte) (uint64, error) {
	return senderKeyID(ciphertext)
}

type server struct {
	handle *beaconcrypt.Server
}

func (s *server) IdentityPK() ([]byte, error) { return s.handle.IdentityPK() }

func (s *server) Register(registration, initial []byte) (engine.Registration, error) {
	if err := validateRegistration(registration); err != nil {
		return engine.Registration{}, err
	}
	registered, err := s.handle.RegisterBeacon(registration, initial)
	if err != nil {
		return engine.Registration{}, mutationError(err)
	}
	return engine.Registration{Data: registered.Serialized, KeyID: registered.KeyID}, nil
}

func (s *server) Encrypt(keyID uint64, plaintext []byte) (engine.Update, error) {
	updated, err := s.handle.EncryptAndUpdate(keyID, plaintext)
	if err != nil {
		return engine.Update{}, mutationError(err)
	}
	// State is an inert, secret-bearing observation, not a durable checkpoint.
	// Only Export provides the restorable whole-server state used by the engine.
	return engine.Update{Data: updated.Data, KeyID: updated.KeyID, Seq: updated.Seq}, nil
}

func (s *server) Decrypt(ciphertext []byte) (engine.Update, error) {
	updated, err := s.handle.DecryptAndUpdate(ciphertext)
	if err != nil {
		return engine.Update{}, mutationError(err)
	}
	return engine.Update{Data: updated.Data, KeyID: updated.KeyID, Seq: updated.Seq}, nil
}

func (s *server) Export() ([]byte, error) { return s.handle.ExportState() }

func (s *server) Close() { s.handle.Close() }
