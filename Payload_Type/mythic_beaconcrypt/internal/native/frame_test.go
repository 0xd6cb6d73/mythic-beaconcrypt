package native

import (
	"bytes"
	"errors"
	"testing"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/engine"
)

func TestSenderKeyIDSupportsDeterministicCBORWidths(t *testing.T) {
	for _, value := range []uint64{0, 23, 24, 255, 256, 65535, 65536, 1<<32 - 1, 1 << 32, 1<<63 + 19, ^uint64(0)} {
		encoded := makeFrame(42, value, 8193)
		kid, err := (Factory{}).SenderKeyID(encoded)
		if err != nil || kid != value {
			t.Fatalf("sender=%d want=%d err=%v", kid, value, err)
		}
		if value != 0 {
			if _, err := (Factory{}).SenderKeyID(makeFrame(value, 7, 81)); err != nil {
				t.Fatalf("sequence=%d: %v", value, err)
			}
		}
	}
}

func TestSenderKeyIDRejectsMalformedAndConcatenatedFrames(t *testing.T) {
	valid := makeFrame(1, 7, 81)
	inputs := map[string][]byte{
		"empty":             nil,
		"short header":      valid[:2],
		"truncated":         valid[:len(valid)-1],
		"invalid CBOR":      bytes.Repeat([]byte{255}, 8),
		"trailing":          append(bytes.Clone(valid), 0),
		"second frame":      append(bytes.Clone(valid), valid...),
		"zero seq":          makeFrame(0, 7, 81),
		"empty body":        makeFrame(1, 7, 80),
		"wrong version":     append([]byte{0x85, 2}, valid[2:]...),
		"wrong kind":        append([]byte{0x85, 1, 1}, valid[3:]...),
		"extra field":       append([]byte{0x86}, valid[1:]...),
		"indefinite array":  append([]byte{0x9f}, valid[1:]...),
		"nonminimal seq":    append([]byte{0x85, 1, 2, 0x18, 1}, valid[4:]...),
		"nonminimal key":    append([]byte{0x85, 1, 2, 1, 0x18, 7}, valid[5:]...),
		"nonminimal length": append([]byte{0x85, 1, 2, 1, 7, 0x59, 0, 81}, valid[7:]...),
		"indefinite bytes":  append([]byte{0x85, 1, 2, 1, 7, 0x5f}, valid[7:]...),
		"text ciphertext":   append([]byte{0x85, 1, 2, 1, 7, 0x78, 81}, valid[7:]...),
		"negative key":      append([]byte{0x85, 1, 2, 1, 0x20}, valid[5:]...),
		"nested sequence":   append([]byte{0x85, 1, 2, 0x81, 1}, valid[4:]...),
		"huge byte length":  {0x85, 1, 2, 1, 7, 0x5b, 255, 255, 255, 255, 255, 255, 255, 255},
		"old Cap'n Proto":   {0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			if _, err := (Factory{}).SenderKeyID(input); !errors.Is(err, ErrInvalidFrame) {
				t.Fatalf("invalid frame accepted: %v", err)
			}
		})
	}
}

func TestSenderKeyIDHonorsCompleteNativeWireLimit(t *testing.T) {
	if engine.MaxProviderMessageBytes != beaconcrypt.MaxMessageSize {
		t.Fatal("provider message limit differs from the pinned Beaconcrypt binding")
	}
	// Prefix, two single-byte integers, and a five-byte byte-string header.
	encoded := makeFrame(1, 7, beaconcrypt.MaxMessageSize-10)
	if len(encoded) != beaconcrypt.MaxMessageSize {
		t.Fatalf("fixture length %d", len(encoded))
	}
	if kid, err := (Factory{}).SenderKeyID(encoded); err != nil || kid != 7 {
		t.Fatalf("inclusive native limit: sender=%d err=%v", kid, err)
	}
	if _, err := (Factory{}).SenderKeyID(append(encoded, 0)); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("oversized input accepted: %v", err)
	}
}

func FuzzSenderKeyID(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{255}, 8))
	f.Add(makeFrame(1, 7, 81))
	f.Add([]byte{0x85, 1, 2, 1, 7, 0x5b, 255, 255, 255, 255, 255, 255, 255, 255})
	f.Fuzz(func(_ *testing.T, input []byte) {
		_, _ = (Factory{}).SenderKeyID(input)
	})
}

func makeFrame(sequence, keyID uint64, payloadSize int) []byte {
	encoded := []byte{0x85, 1, 2}
	encoded = appendCBORArgument(encoded, 0, sequence)
	encoded = appendCBORArgument(encoded, 0, keyID)
	encoded = appendCBORArgument(encoded, 2, uint64(payloadSize))
	return append(encoded, bytes.Repeat([]byte{'x'}, payloadSize)...)
}

func appendCBORArgument(encoded []byte, major byte, value uint64) []byte {
	if value < 24 {
		return append(encoded, major<<5|byte(value))
	}
	var width, information uint
	switch {
	case value <= 0xff:
		width, information = 1, 24
	case value <= 0xffff:
		width, information = 2, 25
	case value <= 0xffffffff:
		width, information = 4, 26
	default:
		width, information = 8, 27
	}
	encoded = append(encoded, major<<5|byte(information))
	for shift := width * 8; shift > 0; shift -= 8 {
		encoded = append(encoded, byte(value>>(shift-8)))
	}
	return encoded
}
