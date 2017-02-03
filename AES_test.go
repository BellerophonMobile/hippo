package hippo

import (
	"testing"
	"github.com/stretchr/testify/require"
)

var algorithms = []string {
	AlgorithmAES_256_CBC,
	AlgorithmAES_256_GCM,
}

func Test_AES_Basic(t *testing.T) {
	for _,a := range(algorithms) {
		t.Run(a, func(t *testing.T) {
			test_skcipher_basic(t, a)
		})
	}
}

func Test_AES_JSON(t *testing.T) {
	for _,a := range(algorithms) {
		t.Run(a, func(t *testing.T) {
			test_skcipher_json(t, a)
		})
	}
}

func Test_AES_Bogus_Key(t *testing.T) {

	for _,a := range(algorithms) {
		t.Run(a, func(t *testing.T) {

			data := []byte("Four score and seven years ago")
			
			keys, err := GenerateSKCipher(a)
			require.Nil(t, err)
			require.NotNil(t, keys)

			bogus, err := GenerateSKCipher(a)
			require.Nil(t, err)
			require.NotNil(t, keys)

			ciphertext, err := keys.Encrypt(data)
			require.Nil(t, err)
			require.NotNil(t, ciphertext)

			cleartext, err := bogus.Decrypt(ciphertext)
			require.NotNil(t, err)
			require.Nil(t, cleartext)

		})
	}
			
}

func Test_AES_Bogus_Data(t *testing.T) {

	// CBC doesn't always generate an error on this

	algorithms := []string{
		AlgorithmAES_256_GCM,		
	}
	
	for _,a := range(algorithms) {
		t.Run(a, func(t *testing.T) {
	
			data := []byte("Four score and seven years ago")
			
			keys, err := GenerateSKCipher(a)
			require.Nil(t, err)
			require.NotNil(t, keys)

			bogus, err := GenerateSKCipher(a)
			require.Nil(t, err)
			require.NotNil(t, keys)

			ciphertext, err := bogus.Encrypt(data)
			require.Nil(t, err)
			require.NotNil(t, ciphertext)

			cleartext, err := keys.Decrypt(ciphertext)
			require.NotNil(t, err)
			require.Nil(t, cleartext)
			
		})
	}
	
}
