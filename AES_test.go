package hippo

import (
	"testing"
)

func Test_AES_01(t *testing.T) {

	test_cipher_basic(t, AlgorithmAES_256_CBC)

}

func Test_AES_02(t *testing.T) {

	test_cipher_bogus_key(t, AlgorithmAES_256_CBC)

}

func Test_AES_03(t *testing.T) {

	test_cipher_bogus_data(t, AlgorithmAES_256_CBC)

}

func Test_AES_04(t *testing.T) {

	test_cipher_json_private(t, AlgorithmAES_256_CBC)

}
