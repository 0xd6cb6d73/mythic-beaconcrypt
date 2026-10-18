package native

import (
	"bytes"
	"errors"
	"testing"

	"capnproto.org/go/capnp/v3"
)

func TestSenderKeyIDSupportsSegmentedFrames(t *testing.T) {
	for _, segmented := range []bool{false, true} {
		encoded := makeFrame(t, 42, 1<<63+19, 8193, segmented)
		kid, err := (Factory{}).SenderKeyID(encoded)
		if err != nil || kid != 1<<63+19 {
			t.Fatalf("segmented=%t sender=%d err=%v", segmented, kid, err)
		}
	}
}

func TestSenderKeyIDRejectsMalformedAndConcatenatedFrames(t *testing.T) {
	valid := makeFrame(t, 1, 7, 81, false)
	for name, input := range map[string][]byte{
		"empty":        nil,
		"short header": valid[:7],
		"truncated":    valid[:len(valid)-1],
		"segments":     bytes.Repeat([]byte{255}, 8),
		"trailing":     append(append([]byte(nil), valid...), 0),
		"second frame": append(append([]byte(nil), valid...), valid...),
		"zero seq":     makeFrame(t, 0, 7, 81, false),
		"empty body":   makeFrame(t, 1, 7, 80, false),
		"null root":    make([]byte, 8),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := (Factory{}).SenderKeyID(input); !errors.Is(err, ErrInvalidFrame) {
				t.Fatalf("invalid frame accepted: %v", err)
			}
		})
	}
}

func FuzzSenderKeyID(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{255}, 8))
	f.Add([]byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(_ *testing.T, input []byte) {
		_, _ = (Factory{}).SenderKeyID(input)
	})
}

func makeFrame(t *testing.T, sequence, keyID uint64, payloadSize int, segmented bool) []byte {
	t.Helper()
	var message *capnp.Message
	var segment *capnp.Segment
	if segmented {
		message, segment = capnp.NewMultiSegmentMessage(nil)
	} else {
		message, segment = capnp.NewSingleSegmentMessage(nil)
	}
	defer message.Release()
	// Place the body first, then create the root in its segment. A large body
	// forces another segment, so reading the root exercises a far pointer too.
	var body capnp.UInt8List
	if segmented {
		var err error
		body, err = capnp.NewData(segment, bytes.Repeat([]byte{'x'}, payloadSize))
		if err != nil {
			t.Fatal(err)
		}
		segment = body.Segment()
	}
	frame, err := capnp.NewRootStruct(segment, capnp.ObjectSize{DataSize: 16, PointerCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	frame.SetUint64(0, sequence)
	frame.SetUint64(8, keyID)
	if segmented {
		if err := frame.SetPtr(0, body.ToPtr()); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := frame.SetData(0, bytes.Repeat([]byte{'x'}, payloadSize)); err != nil {
			t.Fatal(err)
		}
	}
	if segmented && message.NumSegments() < 2 {
		t.Fatal("fixture did not exercise segment routing")
	}
	encoded, err := message.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
