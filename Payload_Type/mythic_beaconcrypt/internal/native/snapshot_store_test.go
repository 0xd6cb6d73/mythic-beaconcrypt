package native

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/engine"
)

// This test-only store evaluates the binding's durable callback contract.
// The production provider deliberately commits its checkpoint, routing metadata,
// and exact operation result together through Mythic's storage transaction.
// A native SnapshotStore receives a replacement before the operation returns its
// result, so persisting only here would split that atomic boundary.
type callerSnapshotStore struct {
	mu                                sync.Mutex
	snapshot                          []byte
	head                              *beaconcrypt.SnapshotHead
	loads, swaps                      int
	beforeWriteError, afterWriteError error
	rejectCAS                         bool
}

func (s *callerSnapshotStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	return bytes.Clone(s.snapshot), nil
}

func (s *callerSnapshotStore) CompareAndSwap(expected *beaconcrypt.SnapshotHead, replacement []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.swaps++
	if s.rejectCAS || (s.head == nil) != (expected == nil) || expected != nil && *expected != *s.head {
		return false, nil
	}
	if s.beforeWriteError != nil {
		return false, s.beforeWriteError
	}
	head, err := beaconcrypt.ValidateSnapshotSuccessor(replacement, expected)
	if err != nil {
		return false, err
	}
	s.snapshot, s.head = bytes.Clone(replacement), &head
	if s.afterWriteError != nil {
		return false, s.afterWriteError
	}
	return true, nil
}

func (s *callerSnapshotStore) current() ([]byte, beaconcrypt.SnapshotHead, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var head beaconcrypt.SnapshotHead
	if s.head != nil {
		head = *s.head
	}
	return bytes.Clone(s.snapshot), head, s.loads, s.swaps
}

func TestCallerSnapshotStoreCommitsBeforeReturnAndRestoreClaimsHead(t *testing.T) {
	server, client, keyID, store := callerStoredPair(t)
	beforeBytes, before, _, swaps := store.current()
	if swaps < 2 || before.Generation+1 != uint64(swaps) {
		t.Fatalf("creation and registration not committed: generation=%d swaps=%d", before.Generation, swaps)
	}
	if owner, err := server.Head(); err != nil || owner != before {
		t.Fatalf("registration returned before the authoritative head matched: %v", err)
	}
	update, err := server.EncryptAndUpdate(keyID, []byte("already durable when returned"))
	if err != nil {
		t.Fatal(err)
	}
	afterBytes, after, _, _ := store.current()
	if _, err := beaconcrypt.ValidateSnapshotSuccessor(afterBytes, &before); err != nil || after.Generation != before.Generation+1 {
		t.Fatalf("send did not commit its exact successor: %v", err)
	}
	if plaintext, err := client.DecryptServerMessage(update.Data); err != nil || string(plaintext) != "already durable when returned" {
		t.Fatalf("committed send could not be consumed: %v", err)
	}
	// Neither the store's load result nor native export may alias its trusted bytes.
	beforeBytes[0] ^= 1
	exported, err := server.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	exported[0] ^= 1
	unchanged, _, _, _ := store.current()
	if !bytes.Equal(unchanged, afterBytes) {
		t.Fatal("caller-owned bytes modified the authoritative snapshot")
	}
	server.Close()
	restored, err := beaconcrypt.RestoreServer(store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.Close)
	activatedBytes, activated, _, _ := store.current()
	if _, err := beaconcrypt.ValidateSnapshotSuccessor(activatedBytes, &after); err != nil || activated.Generation != after.Generation+1 {
		t.Fatalf("restore did not durably claim the next generation: %v", err)
	}
	frame, err := client.EncryptToServer([]byte("same live client after caller-store restore"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := restored.DecryptBeaconMessage(frame)
	if err != nil || string(plaintext) != "same live client after caller-store restore" {
		t.Fatalf("restored caller-store ratchet lost continuity: %v", err)
	}
}

func TestCallerSnapshotStoreRejectedReceiveDoesNotLoadOrSwap(t *testing.T) {
	server, client, _, store := callerStoredPair(t)
	frame, err := client.EncryptToServer([]byte("original valid packet"))
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes, before, loads, swaps := store.current()
	output, err := server.DecryptAndUpdate(corruptFrame(t, frame))
	var persistenceError *beaconcrypt.PersistenceError
	if output != nil || !errors.Is(err, beaconcrypt.ErrCrypto) || errors.As(err, &persistenceError) || server.IsPoisoned() {
		t.Fatalf("rejected receive became a persistence failure: output=%v err=%v", output, err)
	}
	afterBytes, after, afterLoads, afterSwaps := store.current()
	if after != before || !bytes.Equal(beforeBytes, afterBytes) || afterLoads != loads || afterSwaps != swaps {
		t.Fatal("rejected receive touched the authoritative store")
	}
	output, err = server.DecryptAndUpdate(frame)
	if err != nil || string(output.Data) != "original valid packet" {
		t.Fatalf("normal rejection consumed the valid packet: %v", err)
	}
	_, accepted, _, acceptedSwaps := store.current()
	if accepted.Generation != before.Generation+1 || acceptedSwaps != swaps+1 {
		t.Fatal("accepted receive was not committed before release")
	}
}

func TestCallerSnapshotStoreFailedCASSuppressesOutputAndPoisonsOwner(t *testing.T) {
	for _, operation := range []string{"receive", "send", "registration"} {
		for _, failure := range []string{"mismatch", "unavailable"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				server, client, keyID, store := callerStoredPair(t)
				frame, err := client.EncryptToServer([]byte("must not escape a failed CAS"))
				if err != nil {
					t.Fatal(err)
				}
				var registration []byte
				if operation == "registration" {
					publicKey, err := server.IdentityPK()
					if err != nil {
						t.Fatal(err)
					}
					candidate, err := beaconcrypt.NewBeacon(0, publicKey)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(candidate.Close)
					registration, err = candidate.GenerateRegistration()
					if err != nil {
						t.Fatal(err)
					}
				}
				beforeBytes, before, _, _ := store.current()
				cause := errors.New("trusted storage unavailable")
				if failure == "mismatch" {
					store.rejectCAS = true
				} else {
					store.beforeWriteError = cause
				}
				switch operation {
				case "receive":
					var output *beaconcrypt.EncryptState
					output, err = server.DecryptAndUpdate(frame)
					if output != nil {
						t.Fatal("plaintext escaped a failed CAS")
					}
				case "send":
					var output *beaconcrypt.EncryptState
					output, err = server.EncryptAndUpdate(keyID, []byte("must not escape a failed CAS"))
					if output != nil {
						t.Fatal("ciphertext escaped a failed CAS")
					}
				case "registration":
					var output *beaconcrypt.RegistrationResponse
					output, err = server.RegisterBeacon(registration, []byte("must not escape a failed CAS"))
					if output != nil {
						t.Fatal("registration reply escaped a failed CAS")
					}
				}
				requireCallerPersistenceStatus(t, err, beaconcrypt.StatusStaleGeneration)
				if failure == "unavailable" && !errors.Is(err, cause) {
					t.Fatalf("callback error lost its cause: %v", err)
				}
				afterBytes, after, _, _ := store.current()
				if after != before || !bytes.Equal(afterBytes, beforeBytes) || !server.IsPoisoned() {
					t.Fatal("failed CAS changed the committed head or retained a usable owner")
				}
				output, err := server.EncryptAndUpdate(keyID, []byte("poisoned owner"))
				requireCallerPersistenceStatus(t, err, beaconcrypt.StatusPoisoned)
				if output != nil {
					t.Fatal("poisoned owner released output")
				}
			})
		}
	}
}

func TestCallerSnapshotStoreLostWriteAcknowledgementConsumesWithoutResultJournal(t *testing.T) {
	for _, operation := range []string{"receive", "send"} {
		t.Run(operation, func(t *testing.T) {
			server, client, keyID, store := callerStoredPair(t)
			frame, err := client.EncryptToServer([]byte("accepted but not delivered"))
			if err != nil {
				t.Fatal(err)
			}
			_, before, _, _ := store.current()
			cause := errors.New("snapshot persisted but acknowledgement lost")
			store.afterWriteError = cause
			var output *beaconcrypt.EncryptState
			if operation == "receive" {
				output, err = server.DecryptAndUpdate(frame)
			} else {
				output, err = server.EncryptAndUpdate(keyID, []byte("accepted but not delivered"))
			}
			requireCallerPersistenceStatus(t, err, beaconcrypt.StatusStaleGeneration)
			if output != nil || !errors.Is(err, cause) || !server.IsPoisoned() {
				t.Fatalf("ambiguous commit exposed a result or live owner: %v", err)
			}
			_, written, _, _ := store.current()
			if written.Generation != before.Generation+1 {
				t.Fatal("test did not durably commit the ambiguous transition")
			}
			store.afterWriteError = nil
			server.Close()
			restored, err := beaconcrypt.RestoreServer(store)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(restored.Close)
			if operation == "receive" {
				output, err = restored.DecryptAndUpdate(frame)
				if output != nil || !errors.Is(err, beaconcrypt.ErrCrypto) {
					t.Fatalf("snapshot-only restore unexpectedly recovered consumed plaintext: %v", err)
				}
			} else {
				output, err = restored.EncryptAndUpdate(keyID, []byte("accepted but not delivered"))
				if err != nil || output.Seq != 3 {
					t.Fatalf("snapshot-only retry did not consume a fresh send sequence: seq=%v err=%v", output, err)
				}
				if plaintext, err := client.DecryptServerMessage(output.Data); err != nil || string(plaintext) != "accepted but not delivered" {
					t.Fatalf("live client could not skip the lost send: %v", err)
				}
			}
		})
	}
}

func TestCallerSnapshotStoreRestoreFencesPreviousOwner(t *testing.T) {
	server, _, keyID, store := callerStoredPair(t)
	_, before, _, _ := store.current()
	restored, err := beaconcrypt.RestoreServer(store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.Close)
	_, after, _, _ := store.current()
	if after.Lineage != before.Lineage || after.Generation != before.Generation+1 || after.Digest == before.Digest {
		t.Fatal("restoration did not advance the exact authoritative head")
	}
	output, err := server.EncryptAndUpdate(keyID, []byte("stale owner"))
	requireCallerPersistenceStatus(t, err, beaconcrypt.StatusStaleGeneration)
	if output != nil || !server.IsPoisoned() {
		t.Fatal("previous owner published after another restore claimed its head")
	}
}

func callerStoredPair(t *testing.T) (*beaconcrypt.Server, *beaconcrypt.Beacon, uint64, *callerSnapshotStore) {
	t.Helper()
	store := &callerSnapshotStore{}
	server, err := beaconcrypt.NewServerWithStore(0, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	publicKey, err := server.IdentityPK()
	if err != nil {
		t.Fatal(err)
	}
	client, err := beaconcrypt.NewBeacon(0, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	registration, err := client.GenerateRegistration()
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.RegisterBeacon(registration, []byte("initial authenticated content"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := client.ProcessInitialMessage(response.Serialized)
	if err != nil || string(plaintext) != "initial authenticated content" {
		t.Fatalf("initial caller-store registration failed: %v", err)
	}
	return server, client, response.KeyID, store
}

func requireCallerPersistenceStatus(t *testing.T, err error, status beaconcrypt.PersistenceStatus) {
	t.Helper()
	var persistenceError *beaconcrypt.PersistenceError
	if !errors.As(err, &persistenceError) || persistenceError.Code != status {
		t.Fatalf("expected persistence status %d, got %v", status, err)
	}
}

func TestMutationErrorPreservesTypedPersistenceFailureAndCause(t *testing.T) {
	cause := errors.New("snapshot store callback failed")
	for _, status := range []beaconcrypt.PersistenceStatus{
		beaconcrypt.StatusMissingSnapshot,
		beaconcrypt.StatusStaleGeneration,
		beaconcrypt.StatusGenerationExhausted,
		beaconcrypt.StatusOutputEncoding,
		beaconcrypt.StatusPoisoned,
	} {
		original := &beaconcrypt.PersistenceError{Code: status, Cause: cause}
		wrapped := mutationError(original)
		var typed *beaconcrypt.PersistenceError
		if !errors.Is(wrapped, engine.ErrNativePersistence) || !errors.Is(wrapped, cause) || !errors.As(wrapped, &typed) || typed != original {
			t.Fatalf("typed persistence failure or callback cause lost: %v", wrapped)
		}
	}
	for _, ordinary := range []error{nil, beaconcrypt.ErrCrypto, ErrInvalidRegistration} {
		if wrapped := mutationError(ordinary); wrapped != ordinary || errors.Is(wrapped, engine.ErrNativePersistence) {
			t.Fatalf("ordinary rejection classified as persistence failure: %v", wrapped)
		}
	}
}
