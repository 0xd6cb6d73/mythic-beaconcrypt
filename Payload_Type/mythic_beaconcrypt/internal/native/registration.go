package native

import (
	"bytes"
	"errors"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
)

var ErrInvalidRegistration = errors.New("invalid Beaconcrypt registration")

// validateRegistration admits the pinned deterministic CBOR InitKex array
// [1, 0, identityKey, preKey, oneTimeKey, pqKey] before entering the stateful
// native call. Field lengths come from transport.cddl; algorithm/role tags come
// from pqxdh.rs. Signature, public-key, and freshness checks remain native.
func validateRegistration(encoded []byte) error {
	if len(encoded) > beaconcrypt.MaxMessageSize || !bytes.HasPrefix(encoded, []byte{0x86, 1, 0}) {
		return ErrInvalidRegistration
	}
	input := cborInput(encoded[3:])
	var fields [4][]byte
	for index, size := range [...]int{33, 98, 98, 1249} {
		field, ok := input.byteString()
		if !ok || len(field) != size {
			return ErrInvalidRegistration
		}
		fields[index] = field
	}
	if len(input) != 0 || fields[0][0] != 1 ||
		fields[1][64] != 4 || fields[1][65] != 0x80 ||
		fields[2][64] != 4 || fields[2][65] != 0x81 ||
		fields[3][64] != 3 {
		return ErrInvalidRegistration
	}
	return nil
}
