package hippo

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func test_skcipher_basic(t *testing.T, algorithm string) {

	data := []byte("Four score and seven years ago")

	key, err := GenerateSKCipher(algorithm)
	require.Nil(t, err)
	require.NotNil(t, key)

	ciphertext, err := key.Encrypt(data)
	require.Nil(t, err)
	require.NotNil(t, ciphertext)

	cleartext, err := key.Decrypt(ciphertext)
	require.Nil(t, err)
	require.NotNil(t, cleartext)

	require.Equal(t, cleartext, data)

}

func test_skcipher_json(t *testing.T, algorithm string) {

	data := []byte("Four score and seven years ago")

	key, err := GenerateSKCipher(algorithm)
	require.Nil(t, err)
	require.NotNil(t, key)

	ciphertext, err := key.Encrypt(data)
	require.Nil(t, err)
	require.NotNil(t, ciphertext)

	privatejson, err := json.Marshal(key.SecretKey())
	require.Nil(t, err)

	private := PrivateKey{}
	err = json.Unmarshal(privatejson, &private)
	require.Nil(t, err)

	decrypter, err := NewSKCipher(private)
	require.Nil(t, err)
	require.NotNil(t, decrypter)

	cleartext, err := decrypter.Decrypt(ciphertext)
	require.Nil(t, err)
	require.NotNil(t, cleartext)

	require.Equal(t, cleartext, data)

}
