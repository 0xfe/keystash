package keystash_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/qubit-sh/keystash"
)

func XTestGKMSEncryptDecrypt(t *testing.T) {
	kms, err := keystash.NewKMS("gkms://qubit-secrets:global")
	if err != nil {
		t.Fatalf("can't create GKMS: %v", err)
	}

	cipherText, err := kms.Encrypt(context.Background(), "dev/quid-server", []byte("boo"))
	if err != nil {
		t.Fatalf("encryption error: %v", err)
	}

	plainText, err := kms.Decrypt(context.Background(), "dev/quid-server", cipherText)
	if err != nil {
		t.Fatalf("decryption error: %v", err)
	}

	if string(plainText) != "boo" {
		t.Fatalf("wrong plaintext, want boo, got %v", string(plainText))
	}
}

func TestMemEncryptDecrypt(t *testing.T) {
	kms, err := keystash.NewKMS("memkms://")

	if err != nil {
		t.Fatalf("can't create GKMS: %v", err)
	}

	key := "6368616e676520746869732070617373776f726420746f206120736563726574"
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}

	keySpec := fmt.Sprintf("%s/%s", key, hex.EncodeToString(nonce))
	cipherText, err := kms.Encrypt(context.Background(), keySpec, []byte("boo"))
	if err != nil {
		t.Fatalf("encryption error: %v", err)
	}

	plainText, err := kms.Decrypt(context.Background(), keySpec, cipherText)
	if err != nil {
		t.Fatalf("decryption error: %v", err)
	}

	if string(plainText) != "boo" {
		t.Fatalf("wrong plaintext, want boo, got %v", string(plainText))
	}
}
