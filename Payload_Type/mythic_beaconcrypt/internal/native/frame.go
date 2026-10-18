package native

import (
	"bytes"
	"errors"

	"capnproto.org/go/capnp/v3"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
)

var ErrInvalidFrame = errors.New("invalid Beaconcrypt frame")

// senderKeyID reads untrusted routing metadata from the existing CryptoFrame
// schema. This is an admission check, not authentication. The engine must also
// compare the authenticated KeyID returned by Decrypt with its expected peer.
func senderKeyID(ciphertext []byte) (uint64, error) {
	if len(ciphertext) < 8 || len(ciphertext) > wire.MaxMessageBytes {
		return 0, ErrInvalidFrame
	}
	input := bytes.NewReader(ciphertext)
	decoder := capnp.NewDecoder(input)
	// Bound allocation by the bytes actually supplied, including hostile segment
	// tables. The stream decoder supports far pointers and multiple segments.
	decoder.MaxMessageSize = uint64(len(ciphertext))
	message, err := decoder.Decode()
	if err != nil {
		return 0, ErrInvalidFrame
	}
	defer message.Release()
	if input.Len() != 0 {
		return 0, ErrInvalidFrame
	}
	message.ResetReadLimit(uint64(len(ciphertext)))
	message.DepthLimit = 8
	root, err := message.Root()
	if err != nil {
		return 0, ErrInvalidFrame
	}
	frame := root.Struct()
	// beaconcrypt/src/schema/cryptoframe.capnp assigns seq and keyId to
	// consecutive UInt64 data fields, followed by the cipherText Data pointer.
	// These are schema field offsets, never offsets into serialized bytes.
	if !frame.IsValid() || frame.Size().DataSize < 16 || frame.Size().PointerCount < 1 || frame.Uint64(0) == 0 {
		return 0, ErrInvalidFrame
	}
	payload, err := frame.Ptr(0)
	if err != nil || len(payload.Data()) <= 80 { // AEAD tag (16) + commitment (64).
		return 0, ErrInvalidFrame
	}
	return frame.Uint64(8), nil
}
