package engine

import (
	"bytes"
	"context"
	"testing"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
)

// sizedFrameNative models a native operation whose serialized frame has the
// requested size. The underlying handle still advances its normal test state.
type sizedFrameNative struct {
	Native
	size int
}

func (n *sizedFrameNative) Encrypt(keyID uint64, plaintext []byte) (Update, error) {
	update, err := n.Native.Encrypt(keyID, plaintext)
	if err == nil {
		update.Data = bytes.Repeat([]byte{0xa5}, n.size)
	}
	return update, err
}

func TestMaximumCompleteFrameIsCommittedAndReplayed(t *testing.T) {
	e, factory, store := testEngine(t, Config{})
	if e.Capabilities().MaxMessageBytes != MaxProviderMessageBytes {
		t.Fatal("default does not advertise the complete Beaconcrypt frame budget")
	}
	profile := prepare(t, e)
	session := beginSession(t, e, profile)
	e.native = &sizedFrameNative{Native: e.native, size: MaxProviderMessageBytes}
	request := sessionRequest(wire.Seal, profile, session, []byte("maximum encoded reply"))
	sealed := mustHandle(t, e, request)
	if len(sealed.Message) != MaxProviderMessageBytes || sealed.Message[0] != 0xa5 || sealed.Message[len(sealed.Message)-1] != 0xa5 {
		t.Fatal("complete frame boundary changed during durable commit")
	}
	if len(store.results[request.RequestID].Result) <= MaxProviderMessageBytes {
		t.Fatal("maximum-frame fixture did not exercise durable JSON/base64 expansion")
	}
	request.AuthContext = "refreshed context"
	replayed := mustHandle(t, e, request)
	if !bytes.Equal(sealed.Message, replayed.Message) || factory.encryptCalls != 1 {
		t.Fatal("maximum-size immutable result was lost or encrypted again")
	}
}

func TestNativeFrameAboveMaximumNeverEscapes(t *testing.T) {
	e, factory, _ := testEngine(t, Config{})
	profile := prepare(t, e)
	session := beginSession(t, e, profile)
	e.native = &sizedFrameNative{Native: e.native, size: MaxProviderMessageBytes + 1}
	request := sessionRequest(wire.Seal, profile, session, []byte("oversized encoded reply"))
	response := e.Handle(context.Background(), request)
	requireFailure(t, response, "native_failure", wire.OutcomeUnresolved)
	if len(response.Message) != 0 || e.native != nil {
		t.Fatal("oversized native output escaped or left a potentially advanced ratchet usable")
	}
	replayed := e.Handle(context.Background(), request)
	requireFailure(t, replayed, "native_failure", wire.OutcomeUnresolved)
	if len(replayed.Message) != 0 || factory.encryptCalls != 1 || e.data.Sessions[session.SessionRef].UnresolvedRequestID != request.RequestID {
		t.Fatal("oversized native output was retried instead of replaying its durable failure")
	}
}

func TestRequestAboveMaximumIsRejectedBeforeNativeWork(t *testing.T) {
	e, factory, _ := testEngine(t, Config{})
	profile := prepare(t, e)
	session := beginSession(t, e, profile)
	before := len(e.data.Requests)
	request := sessionRequest(wire.Seal, profile, session, make([]byte, MaxProviderMessageBytes+1))
	requireFailure(t, e.Handle(context.Background(), request), "invalid_input", wire.OutcomeRejected)
	if factory.encryptCalls != 0 || len(e.data.Requests) != before {
		t.Fatal("oversized request reached native work or consumed durable admission")
	}
	mustHandle(t, e, sessionRequest(wire.Seal, profile, session, []byte("still usable")))
}
