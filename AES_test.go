package hippo

import (
	"testing"
	"github.com/stretchr/testify/require"
)

func Test_AES_Basic(t *testing.T) {

	test_skcipher_basic(t, AlgorithmAES_256_CBC)

}

func Test_AES_JSON(t *testing.T) {

	test_skcipher_json(t, AlgorithmAES_256_CBC)

}

func Test_AES_Bogus_Key(t *testing.T) {

	data := []byte("Four score and seven years ago")

	keys, err := GenerateSKCipher(AlgorithmAES_256_CBC)
	require.Nil(t, err)
	require.NotNil(t, keys)

	bogus, err := GenerateSKCipher(AlgorithmAES_256_CBC)
	require.Nil(t, err)
	require.NotNil(t, keys)

	ciphertext, err := keys.Encrypt(data)
	require.Nil(t, err)
	require.NotNil(t, ciphertext)

	cleartext, err := bogus.Decrypt(ciphertext)
	require.NotNil(t, err)
	require.Nil(t, cleartext)

}

