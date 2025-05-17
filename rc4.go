package pkg

import (
	"crypto/sha256"
	"github.com/zeebo/blake3"
)

type ModifiedRC4 struct {
	s    [256]byte
	i, j uint8
}

func NewModifiedRC4(key []byte) *ModifiedRC4 {
	rc4 := &ModifiedRC4{}
	strengthenedKey := blake3.Sum256(key)
	
	// Initialize S-box
	for i := 0; i < 256; i++ {
		rc4.s[i] = byte(i)
	}
	
	// Key shuffling
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(rc4.s[i]) + int(strengthenedKey[i%32])) % 256
		rc4.s[i], rc4.s[j] = rc4.s[j], rc4.s[i]
	}
	return rc4
}

func (rc4 *ModifiedRC4) XORKeyStream(dst, src []byte) {
	for k, v := range src {
		rc4.i++
		rc4.j += rc4.s[rc4.i]
		rc4.s[rc4.i], rc4.s[rc4.j] = rc4.s[rc4.j], rc4.s[rc4.i]
		// FIXED: Remove %256 (already within 0-255 range)
		dst[k] = v ^ rc4.s[rc4.s[rc4.i]+rc4.s[rc4.j]]
		
		// Refresh S-box every 512 bytes
		if k%512 == 0 {
			newS := sha256.Sum256(rc4.s[:])
			copy(rc4.s[:], newS[:])
		}
	}
}