package keystash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("b7b38bdcd2d4abb449d97400bb46eda0"))
	plainMsg := "This is a test private message."

	// Encrypt
	cipherText, err := encrypt(plainMsg, secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, cipherText)

	// Decrypt
	msg, err := decrypt(cipherText, secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, msg)

	// Should be the same message
	assert.Equal(t, msg, plainMsg)

	// Decrypting empty data should return error
	msg, err = decrypt("", secret)
	assert.Error(t, err)

	// Decrypting with wrong key should return error
	var secret2 [32]byte
	copy(secret2[:], []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"))
	msg, err = decrypt(cipherText, secret2)
	assert.Error(t, err)
}

func TestKeyList(t *testing.T) {
	t.Run("new_keylist", func(t *testing.T) {
		keyList, err := NewKeyList([]string{
			"fb1f31d201cf6ff10936e28a8f9f003602944d0a9014a9f22f004d923256d36c",
			"9ee938728c80970dd0cb8c8329bf20f347a4dd747f5520a9c87ef072ae7bb52c",
			"ed9c6ff49c2d86c8493ecab4d5c7b510d0ad5665c7495f56a92a3b992a5f3de8",
		})
		assert.NoError(t, err)
		assert.Len(t, keyList.keys, 3)
	})

	t.Run("new_keylist_from_json:", func(t *testing.T) {
		jsonKeys := `
			[
				"fb1f31d201cf6ff10936e28a8f9f003602944d0a9014a9f22f004d923256d36c",
				"9ee938728c80970dd0cb8c8329bf20f347a4dd747f5520a9c87ef072ae7bb52c",
				"ed9c6ff49c2d86c8493ecab4d5c7b510d0ad5665c7495f56a92a3b992a5f3de8"
			]
		`
		keyList, err := KeyListFromJSON(jsonKeys)
		assert.NoError(t, err)
		assert.Len(t, keyList.keys, 3)
	})

	t.Run("encrypt_decrypt", func(t *testing.T) {
		// Keyring version 1
		keyList, err := NewKeyList([]string{
			"fb1f31d201cf6ff10936e28a8f9f003602944d0a9014a9f22f004d923256d36c",
		})
		assert.NoError(t, err)

		msg1 := "Hello there."
		cipher1, err := keyList.Encrypt(msg1)
		assert.NoError(t, err)
		assert.NotEmpty(t, cipher1)

		// Keyring version 2
		keyList, err = NewKeyList([]string{
			"fb1f31d201cf6ff10936e28a8f9f003602944d0a9014a9f22f004d923256d36c",
			"9ee938728c80970dd0cb8c8329bf20f347a4dd747f5520a9c87ef072ae7bb52c",
		})
		assert.NoError(t, err)

		// version 1 decryption should still work
		decryptedMsg1, err := keyList.Decrypt(cipher1)
		assert.NoError(t, err)
		assert.Equal(t, msg1, decryptedMsg1)

		// encrypt new string with version 2
		msg2 := "This is message 2"
		cipher2, err := keyList.Encrypt(msg2)
		assert.NoError(t, err)
		assert.NotEmpty(t, cipher2)

		// version 2 decryption should work
		decryptedMsg2, err := keyList.Decrypt(cipher2)
		assert.NoError(t, err)
		assert.Equal(t, msg2, decryptedMsg2)

		// Create a totally different keyring:
		keyListX, err := NewKeyList([]string{
			"21c8126e01b4b6ab90fe45996f399c49541aa51679616f2d08728f5b089fa932",
		})
		assert.NoError(t, err)

		// should not be able to decrypt ciphers from the first keyring
		_, err = keyListX.Decrypt(cipher1)
		assert.Error(t, err)

		_, err = keyListX.Decrypt(cipher2)
		assert.Error(t, err)
	})
}
