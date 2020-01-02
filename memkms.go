package keystash

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"strings"

	"github.com/pkg/errors"
)

type MemKMS struct {
	*KMSBase
}

func NewMemKMS() *MemKMS {
	return &MemKMS{
		KMSBase: &KMSBase{"memkms"},
	}
}

func (mkms *MemKMS) Encrypt(ctx context.Context, keySpec string, plainText []byte) ([]byte, error) {
	parts := strings.Split(keySpec, "/")
	if len(parts) < 2 {
		return nil, errors.Errorf("expecting keySpec <key>/<nonce>, got: %v", keySpec)
	}

	// keySpec must decode to 16 bytes (AES-128) or 32 (AES-256)
	key, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, errors.Wrap(err, "MemKMS:Encrypt: key must be 16 bytes (AES-128) or 32 bytes (AES-256), encoded as hex")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "MemKMS:Encrypt: key must be 16 bytes (AES-128) or 32 bytes (AES-256), encoded as hex")
	}

	nonce, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, errors.Wrap(err, "MemKMS:Encrypt: nonce must be 12 bytes encoded as hex")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "Encrypt")
	}

	return aesgcm.Seal(nil, nonce, plainText, nil), nil
}

func (mkms *MemKMS) Decrypt(ctx context.Context, keySpec string, cipherText []byte) ([]byte, error) {
	parts := strings.Split(keySpec, "/")
	if len(parts) < 2 {
		return nil, errors.Errorf("expecting keySpec <key>/<nonce>, got: %v", keySpec)
	}

	// keySpec must decode to 16 bytes (AES-128) or 32 (AES-256)
	key, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, errors.Wrap(err, "MemKMS:Decrypt: key must be 16 bytes (AES-128) or 32 bytes (AES-256), encoded as hex")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "MemKMS:Decrypt: key must be 16 bytes (AES-128) or 32 bytes (AES-256), encoded as hex")
	}

	nonce, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, errors.Wrap(err, "MemKMS:Decrypt: nonce must be 12 bytes encoded as hex")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "Decrypt")
	}

	plainText, err := aesgcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Decrypt")
	}

	return plainText, nil
}
