package native

import (
	"bytes"
	"errors"
	"testing"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/engine"
)

func TestNativeRegistrationMessagesAndCheckpointRestore(t *testing.T) {
	factory := Factory{}
	server, err := factory.New(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	identity, err := server.IdentityPK()
	if err != nil {
		t.Fatal(err)
	}
	beacon, keyID := registerClient(t, server, []byte(`{"authenticated":"initial"}`))

	plaintext := []byte{0, 1, 255, 128, '\n', '{', '}'}
	ciphertext, err := beacon.EncryptToServer(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if sender, err := factory.SenderKeyID(ciphertext); err != nil || sender != keyID {
		t.Fatalf("native sender/schema compatibility: sender=%d err=%v", sender, err)
	}
	opened, err := server.Decrypt(ciphertext)
	if err != nil || !bytes.Equal(opened.Data, plaintext) || opened.KeyID != keyID || opened.Seq != 1 {
		t.Fatalf("open: update=%+v err=%v", opened, err)
	}
	sealed, err := server.Encrypt(keyID, plaintext)
	if err != nil || sealed.KeyID != keyID || sealed.Seq != 2 {
		t.Fatalf("seal: update=%+v err=%v", sealed, err)
	}
	decrypted, err := beacon.DecryptServerMessage(sealed.Data)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("client open: data=%x err=%v", decrypted, err)
	}

	valid, err := beacon.EncryptToServer([]byte("valid after corrupted packet"))
	if err != nil {
		t.Fatal(err)
	}
	before := exportServer(t, server)
	if _, err := server.Decrypt(corruptFrame(t, valid)); !errors.Is(err, beaconcrypt.ErrCrypto) {
		t.Fatalf("corrupted ciphertext: %v", err)
	}
	if !bytes.Equal(before, exportServer(t, server)) {
		t.Fatal("rejected native receive changed authoritative checkpoint")
	}
	if opened, err := server.Decrypt(valid); err != nil || string(opened.Data) != "valid after corrupted packet" || opened.Seq != 2 {
		t.Fatalf("original ciphertext after rejection: update=%+v err=%v", opened, err)
	}
	before = exportServer(t, server)
	if _, err := server.Decrypt(valid); !errors.Is(err, beaconcrypt.ErrCrypto) {
		t.Fatalf("replay accepted: %v", err)
	}
	if !bytes.Equal(before, exportServer(t, server)) {
		t.Fatal("replay changed authoritative checkpoint")
	}

	checkpoint := exportServer(t, server)
	server.Close()
	restored, err := factory.Restore(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restoredIdentity, err := restored.IdentityPK()
	if err != nil || !bytes.Equal(identity, restoredIdentity) {
		t.Fatalf("restored identity: err=%v", err)
	}
	if bytes.Equal(checkpoint, exportServer(t, restored)) {
		t.Fatal("restore did not advance activation checkpoint")
	}
	resume, err := beacon.EncryptToServer([]byte("same live client after server restore"))
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := restored.Decrypt(resume); err != nil || string(opened.Data) != "same live client after server restore" || opened.Seq != 3 {
		t.Fatalf("resumed open: update=%+v err=%v", opened, err)
	}
	if _, err := factory.Restore([]byte("invalid checkpoint")); err == nil {
		t.Fatal("invalid checkpoint restored")
	}
}

func TestNativeSenderPrecheckPreservesOtherSession(t *testing.T) {
	factory := Factory{}
	server, err := factory.New(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_, firstKeyID := registerClient(t, server, []byte("first session"))
	second, secondKeyID := registerClient(t, server, []byte("second session"))
	if firstKeyID == secondKeyID {
		t.Fatal("registration reused key ID")
	}
	// Exercise a large native CBOR frame as well as the Go-generated parser
	// fixtures. This packet must remain usable after a wrong-route admission.
	plaintext := bytes.Repeat([]byte{0, 255, 128, 1}, 16384)
	ciphertext, err := second.EncryptToServer(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	before := exportServer(t, server)
	sender, err := factory.SenderKeyID(ciphertext)
	if err != nil || sender != secondKeyID {
		t.Fatalf("read native sender: sender=%d err=%v", sender, err)
	}
	if sender == firstKeyID {
		t.Fatal("other session passed expected-session admission")
	}
	if !bytes.Equal(before, exportServer(t, server)) {
		t.Fatal("sender admission consumed native state")
	}
	opened, err := server.Decrypt(ciphertext)
	if err != nil || opened.KeyID != secondKeyID || !bytes.Equal(opened.Data, plaintext) {
		t.Fatalf("correct route could not consume original packet: key=%d err=%v", opened.KeyID, err)
	}
}

func registerClient(t *testing.T, server engine.Native, initial []byte) (*beaconcrypt.Beacon, uint64) {
	t.Helper()
	pk, err := server.IdentityPK()
	if err != nil {
		t.Fatal(err)
	}
	beacon, err := beaconcrypt.NewBeacon(0, pk)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(beacon.Close)
	registration, err := beacon.GenerateRegistration()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := server.Register(registration, initial)
	if err != nil || reply.KeyID == 0 {
		t.Fatalf("register: reply=%+v err=%v", reply, err)
	}
	decrypted, err := beacon.ProcessInitialMessage(reply.Data)
	if err != nil || !bytes.Equal(decrypted, initial) {
		t.Fatalf("authenticated initial response: data=%x err=%v", decrypted, err)
	}
	return beacon, reply.KeyID
}

func exportServer(t *testing.T, server engine.Native) []byte {
	t.Helper()
	checkpoint, err := server.Export()
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func corruptFrame(t *testing.T, ciphertext []byte) []byte {
	t.Helper()
	if len(ciphertext) == 0 {
		t.Fatal("cannot corrupt empty ciphertext")
	}
	corrupted := bytes.Clone(ciphertext)
	// The final byte belongs to the opaque commitment byte string. Corrupting
	// it preserves CBOR framing while forcing native authentication to reject.
	corrupted[len(corrupted)-1] ^= 1
	return corrupted
}
