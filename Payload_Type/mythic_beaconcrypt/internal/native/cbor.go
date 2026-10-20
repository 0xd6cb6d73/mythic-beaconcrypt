package native

// cborInput borrows only the primitive values present in Beaconcrypt's
// fixed transport arrays. It rejects nonminimal/indefinite encodings, containers,
// and truncated values without allocating from untrusted lengths. The Go binding
// exposes no nonmutating transport inspection API; native code still authenticates
// every admitted message using its generated EverCBOR parser.
type cborInput []byte

func (input *cborInput) argument(major byte) (uint64, bool) {
	remaining := *input
	if len(remaining) == 0 || remaining[0]>>5 != major {
		return 0, false
	}
	information := remaining[0] & 0x1f
	remaining = remaining[1:]
	if information < 24 {
		*input = remaining
		return uint64(information), true
	}
	if information > 27 {
		return 0, false
	}
	width := 1 << (information - 24)
	if len(remaining) < width {
		return 0, false
	}
	var value uint64
	for _, octet := range remaining[:width] {
		value = value<<8 | uint64(octet)
	}
	minimum := [...]uint64{24, 1 << 8, 1 << 16, 1 << 32}[information-24]
	if value < minimum {
		return 0, false
	}
	*input = remaining[width:]
	return value, true
}

func (input *cborInput) byteString() ([]byte, bool) {
	size, ok := input.argument(2)
	if !ok || size > uint64(len(*input)) {
		return nil, false
	}
	field := (*input)[:int(size)]
	*input = (*input)[int(size):]
	return field, true
}
