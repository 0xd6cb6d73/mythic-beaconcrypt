package native

import (
	"bytes"
	"errors"
	"testing"

	"capnproto.org/go/capnp/v3"
	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
)

func TestRegistrationPreflightAcceptsExistingStructureWithoutAuthenticating(t *testing.T) {
	for _, segmented := range []bool{false, true} {
		encoded := registrationFrame(t, segmented, 4)
		if err := validateRegistration(encoded); err != nil {
			t.Fatalf("segmented=%t: %v", segmented, err)
		}
		// Native read_message accepts the first unpacked frame. Preserve that
		// behavior instead of imposing a different transport framing rule.
		if err := validateRegistration(append(encoded, 255)); err != nil {
			t.Fatalf("first-frame compatibility: %v", err)
		}
	}
	// The fixture has zero signatures and synthetic public-key bytes. Passing
	// this preflight grants no authenticity; native verification must still run.
}

func TestRegistrationPreflightRejectsMalformedFields(t *testing.T) {
	valid := registrationFrame(t, false, 4)
	inputs := map[string][]byte{
		"AQ==":             {1},
		"empty":            nil,
		"truncated":        valid[:len(valid)-1],
		"segment table":    bytes.Repeat([]byte{255}, 8),
		"missing pointers": registrationFrame(t, false, 3),
		"null root":        make([]byte, 8),
	}
	for field, name := range []string{"identity", "prekey", "one-time", "pqkey"} {
		inputs[name+" length"] = changeRegistrationField(t, valid, field, func(value []byte) []byte { return value[:len(value)-1] })
	}
	for _, field := range []int{0, 1, 2, 3} {
		index := 64
		if field == 0 {
			index = 0
		}
		inputs[[]string{"identity tag", "prekey tag", "one-time tag", "pqkey tag"}[field]] = changeRegistrationField(t, valid, field, func(value []byte) []byte {
			value[index] ^= 1
			return value
		})
	}
	inputs["prekey role"] = changeRegistrationField(t, valid, 1, func(value []byte) []byte { value[65] = 0x81; return value })
	inputs["one-time role"] = changeRegistrationField(t, valid, 2, func(value []byte) []byte { value[65] = 0x80; return value })
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			if err := validateRegistration(input); !errors.Is(err, ErrInvalidRegistration) {
				t.Fatalf("malformed registration accepted: %v", err)
			}
		})
	}
}

func TestNativeMalformedRegistrationLeavesCheckpointUnchanged(t *testing.T) {
	server, err := (Factory{}).New(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	identity, err := server.IdentityPK()
	if err != nil {
		t.Fatal(err)
	}
	client, err := beaconcrypt.NewBeacon(0, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	registration, err := client.GenerateRegistration()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRegistration(registration); err != nil {
		t.Fatalf("generated client registration rejected: %v", err)
	}
	before := exportServer(t, server)
	for name, invalid := range map[string][]byte{
		"AQ==":         {1},
		"truncated":    registration[:len(registration)-1],
		"bad identity": changeRegistrationField(t, registration, 0, func(value []byte) []byte { value[0] = 0; return value }),
		"bad role":     changeRegistrationField(t, registration, 1, func(value []byte) []byte { value[65] = 0x81; return value }),
		"short pqkey":  changeRegistrationField(t, registration, 3, func(value []byte) []byte { return value[:len(value)-1] }),
	} {
		t.Run(name, func(t *testing.T) {
			response, err := server.Register(invalid, []byte("initial"))
			if !errors.Is(err, ErrInvalidRegistration) || len(response.Data) != 0 || response.KeyID != 0 {
				t.Fatalf("malformed registration reached native state: response=%+v err=%v", response, err)
			}
			if !bytes.Equal(before, exportServer(t, server)) {
				t.Fatal("preflight rejection changed native checkpoint")
			}
		})
	}
	initial := []byte("real client registration remains usable")
	response, err := server.Register(registration, initial)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := client.ProcessInitialMessage(response.Data)
	if err != nil || !bytes.Equal(opened, initial) {
		t.Fatalf("real client rejected registration reply: %v", err)
	}
}

func FuzzRegistrationPreflight(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add(bytes.Repeat([]byte{255}, 8))
	f.Fuzz(func(_ *testing.T, input []byte) {
		_ = validateRegistration(input)
	})
}

func registrationFrame(t *testing.T, segmented bool, pointers uint16) []byte {
	t.Helper()
	fields := [4][]byte{make([]byte, 33), make([]byte, 98), make([]byte, 98), make([]byte, 1249)}
	fields[0][0], fields[1][64], fields[1][65], fields[2][64], fields[2][65], fields[3][64] = 1, 4, 0x80, 4, 0x81, 3
	var message *capnp.Message
	var segment *capnp.Segment
	if segmented {
		message, segment = capnp.NewMultiSegmentMessage(nil)
		padding, err := capnp.NewData(segment, make([]byte, 8193))
		if err != nil {
			t.Fatal(err)
		}
		segment = padding.Segment()
	} else {
		message, segment = capnp.NewSingleSegmentMessage(nil)
	}
	defer message.Release()
	root, err := capnp.NewRootStruct(segment, capnp.ObjectSize{PointerCount: pointers})
	if err != nil {
		t.Fatal(err)
	}
	for index := uint16(0); index < pointers; index++ {
		if err := root.SetData(index, fields[index]); err != nil {
			t.Fatal(err)
		}
	}
	if segmented && message.NumSegments() < 2 {
		t.Fatal("fixture did not exercise multiple segments")
	}
	encoded, err := message.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func changeRegistrationField(t *testing.T, encoded []byte, field int, change func([]byte) []byte) []byte {
	t.Helper()
	message, err := capnp.Unmarshal(bytes.Clone(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer message.Release()
	root, err := message.Root()
	if err != nil {
		t.Fatal(err)
	}
	// Decoded arenas are read-only. Rebuild the four public Data fields into a
	// writable message instead of relying on input-buffer capacity for edits.
	modified, segment := capnp.NewSingleSegmentMessage(nil)
	defer modified.Release()
	modifiedRoot, err := capnp.NewRootStruct(segment, capnp.ObjectSize{PointerCount: 4})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		pointer, err := root.Struct().Ptr(uint16(index))
		if err != nil {
			t.Fatal(err)
		}
		data := bytes.Clone(pointer.Data())
		if index == field {
			data = change(data)
		}
		if err := modifiedRoot.SetData(uint16(index), data); err != nil {
			t.Fatal(err)
		}
	}
	result, err := modified.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return result
}
