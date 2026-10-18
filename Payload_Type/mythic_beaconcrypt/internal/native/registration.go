package native

import (
	"bytes"
	"errors"

	"capnproto.org/go/capnp/v3"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
)

var ErrInvalidRegistration = errors.New("invalid Beaconcrypt registration")

// validateRegistration admits the existing unpacked InitKex structure before
// entering the stateful native registration call. These lengths and tags come
// from phase1.capnp and beaconcrypt-core/src/pqxdh.rs at the pinned commit.
// Signature, public-key, and registration freshness checks remain native.
func validateRegistration(encoded []byte) error {
	if len(encoded) < 8 || len(encoded) > wire.MaxMessageBytes {
		return ErrInvalidRegistration
	}
	decoder := capnp.NewDecoder(bytes.NewReader(encoded))
	decoder.MaxMessageSize = uint64(len(encoded))
	message, err := decoder.Decode()
	if err != nil {
		return ErrInvalidRegistration
	}
	defer message.Release()
	// Match native read_message's first-frame behavior, including any bytes
	// following that frame. Do not impose a new wire canonicalization rule.
	message.ResetReadLimit(uint64(len(encoded)))
	message.DepthLimit = 8
	root, err := message.Root()
	if err != nil {
		return ErrInvalidRegistration
	}
	registration := root.Struct()
	if !registration.IsValid() || registration.Size().PointerCount < 4 {
		return ErrInvalidRegistration
	}
	var fields [4][]byte
	for index, size := range [...]int{33, 98, 98, 1249} {
		pointer, err := registration.Ptr(uint16(index))
		if err != nil {
			return ErrInvalidRegistration
		}
		fields[index] = pointer.Data()
		if len(fields[index]) != size {
			return ErrInvalidRegistration
		}
	}
	// The signed key fields contain the native 64-byte Ed25519 signature
	// followed by their existing algorithm and, for X25519, key-role tags.
	if fields[0][0] != 1 ||
		fields[1][64] != 4 || fields[1][65] != 0x80 ||
		fields[2][64] != 4 || fields[2][65] != 0x81 ||
		fields[3][64] != 3 {
		return ErrInvalidRegistration
	}
	return nil
}
