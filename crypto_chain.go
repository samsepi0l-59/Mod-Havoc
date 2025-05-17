package pkg

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "errors"

    "github.com/zeebo/blake3"
    "golang.org/x/crypto/chacha20poly1305"
)

// CryptoChain holds the per-layer keys and encoders.
type CryptoChain struct {
    aesKey    []byte
    chachaKey []byte
    rc4Key    []byte
    hmacKey   []byte
    base91    *Base91
}

// deriveKey builds a 32-byte key from masterKey and a context string.
func deriveKey(masterKey []byte, context string) []byte {
    hasher, err := blake3.NewKeyed(masterKey)
    if err != nil {
        panic("blake3 Keyed derivation failed: " + err.Error())
    }
    hasher.Write([]byte(context))
    return hasher.Sum(nil) // 32 bytes
}

// NewCryptoChain initializes all sub-keys from a 32-byte masterKey.
func NewCryptoChain(masterKey []byte) (*CryptoChain, error) {
    if len(masterKey) != 32 {
        return nil, errors.New("master key must be 32 bytes")
    }
    return &CryptoChain{
        aesKey:    deriveKey(masterKey, "GHOSTHAVOC-AES"),
        chachaKey: deriveKey(masterKey, "GHOSTHAVOC-CHACHA"),
        rc4Key:    deriveKey(masterKey, "GHOSTHAVOC-RC4"),
        hmacKey:   deriveKey(masterKey, "GHOSTHAVOC-HMAC"),
        base91:    NewBase91(),
    }, nil
}

func (cc *CryptoChain) Encrypt(plaintext []byte) ([]byte, error) {
    // AES-CTR
    aesCipher, err := aes.NewCipher(cc.aesKey)
    if err != nil {
        return nil, err
    }
    aesNonce := make([]byte, aes.BlockSize)
    if _, err := rand.Read(aesNonce); err != nil {
        return nil, err
    }
    aesCTR := cipher.NewCTR(aesCipher, aesNonce)
    aesEncrypted := make([]byte, len(plaintext))
    aesCTR.XORKeyStream(aesEncrypted, plaintext)
    aesEncrypted = append(aesNonce, aesEncrypted...)

    // ChaCha20-Poly1305
    chacha, err := chacha20poly1305.New(cc.chachaKey)
    if err != nil {
        return nil, err
    }
    chachaNonce := make([]byte, chacha.NonceSize())
    if _, err := rand.Read(chachaNonce); err != nil {
        return nil, err
    }
    chachaEncrypted := chacha.Seal(nil, chachaNonce, aesEncrypted, nil)
    chachaEncrypted = append(chachaNonce, chachaEncrypted...)

    // Modified RC4
    rc4 := NewModifiedRC4(cc.rc4Key)
    rc4Encrypted := make([]byte, len(chachaEncrypted))
    rc4.XORKeyStream(rc4Encrypted, chachaEncrypted)

    // Base91 → Base64
    base91Encoded := cc.base91.Encode(rc4Encrypted)
    base64Encoded := base64.StdEncoding.EncodeToString(base91Encoded)

    // Blake3 HMAC (first 32 bytes as tag)
    mac := blake3.New()
    mac.Write(cc.hmacKey)
    mac.Write([]byte(base64Encoded))
    tag := mac.Sum(nil)[:32]

    return append(tag, []byte(base64Encoded)...), nil
}

func (cc *CryptoChain) Decrypt(ciphertext []byte) ([]byte, error) {
    if len(ciphertext) < 32 {
        return nil, errors.New("invalid ciphertext length")
    }
    recvTag := ciphertext[:32]
    payload := ciphertext[32:]

    // HMAC verify
    mac := blake3.New()
    mac.Write(cc.hmacKey)
    mac.Write(payload)
    expected := mac.Sum(nil)[:32]
    if subtle.ConstantTimeCompare(recvTag, expected) != 1 {
        return nil, errors.New("HMAC validation failed")
    }

    // Base64 → Base91
    b64, err := base64.StdEncoding.DecodeString(string(payload))
    if err != nil {
        return nil, err
    }
    b91, err := cc.base91.Decode(b64)
    if err != nil {
        return nil, err
    }

    // RC4 decrypt
    rc4 := NewModifiedRC4(cc.rc4Key)
    rc4Plain := make([]byte, len(b91))
    rc4.XORKeyStream(rc4Plain, b91)

    // ChaCha20-Poly1305
    chacha, err := chacha20poly1305.New(cc.chachaKey)
    if err != nil {
        return nil, err
    }
    ns := chacha.NonceSize()
    if len(rc4Plain) < ns {
        return nil, errors.New("invalid chacha ciphertext")
    }
    nonce, ct := rc4Plain[:ns], rc4Plain[ns:]
    chachaPlain, err := chacha.Open(nil, nonce, ct, nil)
    if err != nil {
        return nil, err
    }

    // AES-CTR
    aesCipher, err := aes.NewCipher(cc.aesKey)
    if err != nil {
        return nil, err
    }
    if len(chachaPlain) < aes.BlockSize {
        return nil, errors.New("invalid aes ciphertext")
    }
    aesNonce, aesCt := chachaPlain[:aes.BlockSize], chachaPlain[aes.BlockSize:]
    ctr := cipher.NewCTR(aesCipher, aesNonce)
    aesPlain := make([]byte, len(aesCt))
    ctr.XORKeyStream(aesPlain, aesCt)

    return aesPlain, nil
}

func (cc *CryptoChain) Wipe() {
    secureWipe(cc.aesKey)
    secureWipe(cc.chachaKey)
    secureWipe(cc.rc4Key)
    secureWipe(cc.hmacKey)
}

func secureWipe(data []byte) {
    for i := range data {
        data[i] = 0
    }
}
