package native

import (
	"bytes"
	"errors"
	"testing"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
)

func TestNativeCompleteFrameLimitRoundTripAndOversizeRecovery(t *testing.T) {
	server, err := (Factory{}).New(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, keyID := registerClient(t, server, []byte("registered"))

	// The first ordinary server frame uses sequence 2 and sender ID 0; the
	// client frame uses sequence 1 and assigned ID 1. Both integers take one
	// byte. Derive the remaining CBOR header width using the schema fixture;
	// the authenticated ciphertext adds its 16-byte tag and 64-byte commitment.
	if keyID != 1 {
		t.Fatalf("unexpected first assigned key ID: %d", keyID)
	}
	header := appendCBORArgument([]byte{0x85, 1, 2, 2, 0}, 2, uint64(beaconcrypt.MaxMessageSize))
	maximumPlaintext := beaconcrypt.MaxMessageSize - len(header) - 16 - 64
	plaintext := bytes.Repeat([]byte{0xa5}, maximumPlaintext+1)

	before := exportServer(t, server)
	if _, err := server.Encrypt(keyID, plaintext); !errors.Is(err, beaconcrypt.ErrCrypto) {
		t.Fatalf("one-byte-oversize server plaintext was not rejected: %v", err)
	}
	if !bytes.Equal(before, exportServer(t, server)) {
		t.Fatal("oversize server send changed its authoritative checkpoint")
	}
	sealed, err := server.Encrypt(keyID, plaintext[:maximumPlaintext])
	if err != nil || len(sealed.Data) != beaconcrypt.MaxMessageSize || sealed.Seq != 2 {
		t.Fatalf("exact maximum server frame: length=%d sequence=%d error=%v", len(sealed.Data), sealed.Seq, err)
	}
	opened, err := client.DecryptServerMessage(sealed.Data)
	if err != nil || !bytes.Equal(opened, plaintext[:maximumPlaintext]) {
		t.Fatalf("client could not decrypt exact maximum server frame: %v", err)
	}

	if _, err := client.EncryptToServer(plaintext); !errors.Is(err, beaconcrypt.ErrCrypto) {
		t.Fatalf("one-byte-oversize client plaintext was not rejected: %v", err)
	}
	packet, err := client.EncryptToServer(plaintext[:maximumPlaintext])
	if err != nil || len(packet) != beaconcrypt.MaxMessageSize {
		t.Fatalf("exact maximum client frame: length=%d error=%v", len(packet), err)
	}
	oversizedPacket := make([]byte, len(packet)+1)
	copy(oversizedPacket, packet)
	before = exportServer(t, server)
	if _, err := server.Decrypt(oversizedPacket); !errors.Is(err, beaconcrypt.ErrCrypto) {
		t.Fatalf("one-byte-oversize encoded client frame was not rejected: %v", err)
	}
	if !bytes.Equal(before, exportServer(t, server)) {
		t.Fatal("oversize encoded receive changed the authoritative checkpoint")
	}
	decrypted, err := server.Decrypt(packet)
	if err != nil || decrypted.KeyID != keyID || decrypted.Seq != 1 || !bytes.Equal(decrypted.Data, plaintext[:maximumPlaintext]) {
		t.Fatalf("server could not decrypt exact maximum client frame after rejection: sequence=%d error=%v", decrypted.Seq, err)
	}
	t.Logf("bidirectional %d-byte encoded frames; server checkpoint=%d bytes", beaconcrypt.MaxMessageSize, len(exportServer(t, server)))
}
