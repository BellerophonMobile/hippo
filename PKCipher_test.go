package hippo

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func test_pkcipher_basic(t *testing.T, algorithm string) {

	data := []byte("Four score and seven years ago")

	keys, err := GeneratePKCipher(algorithm)
	require.Nil(t, err)
	require.NotNil(t, keys)

	ciphertext, err := keys.Encrypt(data)
	require.Nil(t, err)
	require.NotNil(t, ciphertext)

	cleartext, err := keys.Decrypt(ciphertext)
	require.Nil(t, err)
	require.NotNil(t, cleartext)

	require.Equal(t, cleartext, data)

}

func test_pkcipher_json_public(t *testing.T, algorithm string) {

	data := []byte("Four score and seven years ago")

	keys, err := GeneratePKCipher(algorithm)
	require.Nil(t, err)
	require.NotNil(t, keys)

	publicjson, err := json.Marshal(keys.PublicKey())
	require.Nil(t, err)
	require.NotNil(t, publicjson)

	public := PublicKey{}
	err = json.Unmarshal(publicjson, &public)
	require.Nil(t, err)

	encrypter, err := NewEncrypter(public)
	require.Nil(t, err)
	require.NotNil(t, encrypter)

	ciphertext, err := encrypter.Encrypt(data)
	require.Nil(t, err)
	require.NotNil(t, ciphertext)

	cleartext, err := keys.Decrypt(ciphertext)
	require.Nil(t, err)
	require.NotNil(t, cleartext)

	require.Equal(t, cleartext, data)

}

func test_pkcipher_json_private(t *testing.T, algorithm string) {

	data := []byte("Four score and seven years ago")

	keys, err := GeneratePKCipher(algorithm)
	require.Nil(t, err)
	require.NotNil(t, keys)

	ciphertext, err := keys.Encrypt(data)
	require.Nil(t, err)
	require.NotNil(t, ciphertext)

	privatejson, err := json.Marshal(keys.PrivateKey())
	require.Nil(t, err)
	require.NotNil(t, privatejson)
	t.Log("Private Key", string(privatejson))

	private := PrivateKey{}
	err = json.Unmarshal(privatejson, &private)
	require.Nil(t, err)

	decrypter, err := NewDecrypter(private)
	require.Nil(t, err)
	require.NotNil(t, decrypter)

	cleartext, err := decrypter.Decrypt(ciphertext)
	require.Nil(t, err)
	require.NotNil(t, cleartext)

	require.Equal(t, cleartext, data)

}
