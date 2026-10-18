package native

import (
	"bytes"
	"errors"
	"testing"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
)

func TestRegistrationPreflightAcceptsCBORStructureWithoutAuthenticating(t *testing.T) {
	encoded := registrationFrame(4)
	if err := validateRegistration(encoded); err != nil {
		t.Fatal(err)
	}
	// This fixture has zero signatures and synthetic public-key bytes. Passing
	// preflight grants no authenticity; native verification must still run.
}

func TestRegistrationPreflightRejectsMalformedFields(t *testing.T) {
	valid := registrationFrame(4)
	inputs := map[string][]byte{
		"AQ==":             {1},
		"empty":            nil,
		"truncated":        valid[:len(valid)-1],
		"invalid CBOR":     bytes.Repeat([]byte{255}, 8),
		"missing field":    registrationFrame(3),
		"old Cap'n Proto":  make([]byte, 8),
		"trailing":         append(bytes.Clone(valid), 0),
		"second message":   append(bytes.Clone(valid), valid...),
		"wrong version":    append([]byte{0x86, 2}, valid[2:]...),
		"wrong kind":       append([]byte{0x86, 1, 1}, valid[3:]...),
		"wrong fields":     append([]byte{0x85}, valid[1:]...),
		"indefinite array": append([]byte{0x9f}, valid[1:]...),
		"nonminimal bytes": append([]byte{0x86, 1, 0, 0x59, 0, 33}, valid[5:]...),
		"text field":       append([]byte{0x86, 1, 0, 0x78, 33}, valid[5:]...),
		"indefinite bytes": append([]byte{0x86, 1, 0, 0x5f}, valid[5:]...),
		"huge byte length": {0x86, 1, 0, 0x5b, 255, 255, 255, 255, 255, 255, 255, 255},
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
		"trailing":     append(bytes.Clone(registration), 0),
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
	f.Add(registrationFrame(4))
	f.Fuzz(func(_ *testing.T, input []byte) {
		_ = validateRegistration(input)
	})
}

func registrationFrame(fields int) []byte {
	values := [4][]byte{make([]byte, 33), make([]byte, 98), make([]byte, 98), make([]byte, 1249)}
	values[0][0], values[1][64], values[1][65], values[2][64], values[2][65], values[3][64] = 1, 4, 0x80, 4, 0x81, 3
	encoded := []byte{0x86, 1, 0}
	for _, value := range values[:fields] {
		encoded = appendCBORArgument(encoded, 2, uint64(len(value)))
		encoded = append(encoded, value...)
	}
	return encoded
}

func changeRegistrationField(t *testing.T, encoded []byte, field int, change func([]byte) []byte) []byte {
	t.Helper()
	input := cborInput(encoded[3:])
	result := bytes.Clone(encoded[:3])
	for index := 0; index < 4; index++ {
		value, ok := input.byteString()
		if !ok {
			t.Fatal("malformed registration fixture")
		}
		value = bytes.Clone(value)
		if index == field {
			value = change(value)
		}
		result = appendCBORArgument(result, 2, uint64(len(value)))
		result = append(result, value...)
	}
	return result
}
