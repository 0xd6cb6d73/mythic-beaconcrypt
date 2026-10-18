package native

import (
	"bytes"
	"errors"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
)

var ErrInvalidFrame = errors.New("invalid Beaconcrypt frame")

// senderKeyID reads untrusted routing metadata from the pinned deterministic
// CBOR CryptoFrame schema: [1, 2, seq, keyId, cipherText]. This is admission, not
// authentication: the engine also checks the authenticated KeyID from Decrypt.
func senderKeyID(ciphertext []byte) (uint64, error) {
	if len(ciphertext) > beaconcrypt.MaxMessageSize || !bytes.HasPrefix(ciphertext, []byte{0x85, 1, 2}) {
		return 0, ErrInvalidFrame
	}
	input := cborInput(ciphertext[3:])
	sequence, ok := input.argument(0)
	if !ok || sequence == 0 {
		return 0, ErrInvalidFrame
	}
	keyID, ok := input.argument(0)
	if !ok {
		return 0, ErrInvalidFrame
	}
	body, ok := input.byteString()
	if !ok || len(body) <= 80 || len(input) != 0 { // AEAD tag (16) + commitment (64).
		return 0, ErrInvalidFrame
	}
	return keyID, nil
}
