package keystash

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/pkg/errors"
)

type KeyList struct {
	keys [][32]byte
}

// NewKeyring creates a key ring with an array of provided keys.
// Each key in keys should be a hex encoded string of a 32-byte slice.
func NewKeyList(list []string) (*KeyList, error) {
	keys := make([][32]byte, len(list))

	for n := len(keys) - 1; n >= 0; n-- {
		var key [32]byte
		keyBytes, err := hex.DecodeString(list[n])
		if err != nil {
			return nil, errors.Wrap(err, "NewKeyring:DecodeString")
		}
		copy(key[:], keyBytes)
		keys[n] = key
	}

	return &KeyList{
		keys: keys,
	}, nil
}

// KeyringFromJSON loads a keyring from JSON data
func KeyListFromJSON(keysJSON string) (*KeyList, error) {
	var keyList []string
	err := json.Unmarshal([]byte(keysJSON), &keyList)
	if err != nil {
		return nil, errors.Wrap(err, "KeyringFROMJSON:Unmarshal")
	}

	return NewKeyList(keyList)
}

// Encrypt encrypts a string with the keyring's latest key
func (k *KeyList) Encrypt(plaintext string) (string, error) {
	latestKeyIndex := len(k.keys) - 1
	latestKey := k.keys[latestKeyIndex]
	ciphertext, err := encrypt(plaintext, latestKey)
	if err != nil {
		return "", err
	}
	return string(ciphertext), nil
}

// Decrypt decrypts an encrypted string by trying each key in the keyring
func (k *KeyList) Decrypt(ciphertext string) (plaintext string, err error) {
	for n := 0; n < len(k.keys); n++ {
		plaintext, err = decrypt(ciphertext, k.keys[n])
		if err == nil {
			return
		}
	}

	return "", errors.New("cannot decrypt with any key")
}

// encrypt returns an encrypted string using the secret key
func encrypt(plaintext string, secret [32]byte) (string, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}

	encrypted := secretbox.Seal(nonce[:], []byte(plaintext), &nonce, &secret)

	return base64.URLEncoding.EncodeToString(encrypted), nil
}

// decrypt returns a decrypted string using the secret key
func decrypt(cryptedText string, secret [32]byte) (string, error) {
	if cryptedText == "" {
		return "", errors.New("can't decrypt empty string ")
	}

	encrypted, err := base64.URLEncoding.DecodeString(cryptedText)
	if err != nil {
		return "", errors.Wrap(err, "Decrypt:DecodeString")
	}

	cryptedBytes := []byte(encrypted)
	var nonce [24]byte
	copy(nonce[:], cryptedBytes[:24])
	decrypted, ok := secretbox.Open(nil, cryptedBytes[24:], &nonce, &secret)
	if !ok {
		return "", errors.New("failed to decrypt")
	}
	return string(decrypted), nil
}
