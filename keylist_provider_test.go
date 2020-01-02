package keystash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func XTestGKMSKeyListProvider(t *testing.T) {
	t.Run("create_specific", func(t *testing.T) {
		p, err := NewGKMSKeyListProvider("qubit-secrets", "global", "qubit-secrets", "dev/quid-server")
		assert.NoError(t, err)
		assert.NotNil(t, p)

		t.Run("get_key_list", func(t *testing.T) {
			keylist, err := p.GetKeyList("piiKeyList")
			assert.NoError(t, err)
			assert.NotNil(t, keylist)

			t.Run("encrypt_decrypt", func(t *testing.T) {
				msg1 := "Hello there"
				cipher1, err := keylist.Encrypt(msg1)
				assert.NoError(t, err)
				assert.NotEmpty(t, cipher1)

				decipheredMsg, err := keylist.Decrypt(cipher1)
				assert.NoError(t, err)
				assert.Equal(t, msg1, decipheredMsg)
			})
		})
	})

	t.Run("create_with_specs", func(t *testing.T) {
		p, err := NewKeyListProvider("gkms://qubit-secrets:global:qubit-secrets:dev/quid-server")
		assert.NoError(t, err)
		assert.NotNil(t, p)

		t.Run("get_key_list", func(t *testing.T) {
			keylist, err := p.GetKeyList("piiKeyList")
			assert.NoError(t, err)
			assert.NotNil(t, keylist)

			t.Run("encrypt_decrypt", func(t *testing.T) {
				msg1 := "Hello there"
				cipher1, err := keylist.Encrypt(msg1)
				assert.NoError(t, err)
				assert.NotEmpty(t, cipher1)

				decipheredMsg, err := keylist.Decrypt(cipher1)
				assert.NoError(t, err)
				assert.Equal(t, msg1, decipheredMsg)
			})
		})
	})
}

func TestMemKeyListProvider(t *testing.T) {
	keylistData := map[string]string{
		"test": `["caa9b00e54d3f3c7dc5eb705743a3bc1c0439171112d6bc31b0ca3219ab3889b"]`,
	}
	p, err := NewMemKeyListProvider(keylistData)
	assert.NoError(t, err)
	assert.NotNil(t, p)

	t.Run("get_key_list", func(t *testing.T) {
		keylist, err := p.GetKeyList("test")
		assert.NoError(t, err)
		assert.NotNil(t, keylist)
		assert.NotNil(t, keylist.keys)
		assert.Len(t, keylist.keys, 1)

		t.Run("encrypt_decrypt", func(t *testing.T) {
			msg1 := "Hello there"
			cipher1, err := keylist.Encrypt(msg1)
			assert.NoError(t, err)
			assert.NotEmpty(t, cipher1)

			decipheredMsg, err := keylist.Decrypt(cipher1)
			assert.NoError(t, err)
			assert.Equal(t, msg1, decipheredMsg)
		})
	})
}
