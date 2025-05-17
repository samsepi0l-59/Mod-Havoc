package pkg

import (
	"bytes"
	"errors"
)

const base91Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""

type Base91 struct {
	encode [91]byte
	decode [256]byte
}

func NewBase91() *Base91 {
	b := &Base91{}
	copy(b.encode[:], base91Alphabet)
	for i := 0; i < 256; i++ {
		b.decode[i] = 0xFF
	}
	for i, c := range base91Alphabet {
		b.decode[c] = byte(i)
	}
	return b
}

func (b *Base91) Encode(src []byte) []byte {
	var buf bytes.Buffer
	var n, v uint32
	for _, c := range src {
		v |= uint32(c) << n
		n += 8
		for n >= 13 {
			val := v & 0x1FFF
			if val > 88 {
				v >>= 13
				n -= 13
			} else {
				val = v & 0x3FFF
				v >>= 14
				n -= 14
			}
			buf.WriteByte(b.encode[val%91])
			buf.WriteByte(b.encode[val/91])
		}
	}
	if n > 0 {
		buf.WriteByte(b.encode[v%91])
		if n > 7 || v >= 91 {
			buf.WriteByte(b.encode[v/91])
		}
	}
	return buf.Bytes()
}

func (b *Base91) Decode(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	var v, n uint32
	for _, c := range src {
		if b.decode[c] == 0xFF {
			return nil, errors.New("invalid base91 character")
		}
		val := uint32(b.decode[c])
		v |= val << n
		n += 13
		if n >= 32 {
			for i := 0; i < 4; i++ {
				buf.WriteByte(byte(v))
				v >>= 8
			}
			n -= 32
			v = val >> (13 - n)
		}
	}
	return buf.Bytes(), nil
}