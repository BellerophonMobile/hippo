package hippo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// AlgorithmAES_256_CBC is a constant string identifying the AES
// algorithm with 256 bit key and cipher block chaining.
const AlgorithmAES_256_CBC = "aes-256-cbc"

func init() {
	err := RegisterSKCipherer(&aescbc_t{bits: 256})
	if err != nil {
		panic(err)
	}
}

type aescbc_t struct {
	bits int
}

// Algorithm returns the label identifying the algorithm and
// parameterization of this cipherer.
func (x *aescbc_t) Algorithm() string {
	return fmt.Sprintf("aes-%v-cbc", x.bits)
}

// Generate creates a new SKCipher.
func (x *aescbc_t) Generate() (SKCipher, error) {

	var cipher AESCBCSKCipher

	cipher.Algorithm = x.Algorithm()
	cipher.Bits = x.bits

	cipher.Key = make([]byte, x.bits/8)
	_, err := rand.Read(cipher.Key)
	if err != nil {
		return nil, err
	}

	return &cipher, nil

}

// New wraps the given secret key in an SKCipher.
func (x *aescbc_t) New(key PrivateKey) (SKCipher, error) {

	var cipher AESCBCSKCipher
	var err error

	cipher.Algorithm = x.Algorithm()
	cipher.Bits = x.bits

	err = cipher.SetKey(key)
	if err != nil {
		return nil, err
	}

	return &cipher, nil

}

type AESCBCSKCipher struct {
	Algorithm string
	Bits      int
	Key       []byte
}

func (x *AESCBCSKCipher) SecretKey() PrivateKey {

	key := PrivateKey{
		Algorithm: x.Algorithm,
		Private:   base64.RawURLEncoding.EncodeToString(x.Key),
	}

	return key

}

func (x *AESCBCSKCipher) SetKey(key PrivateKey) error {

	if key.Algorithm != x.Algorithm {
		return ErrAlgorithmMismatch
	}

	keydata, ok := key.Private.(string)
	if !ok {
		return fmt.Errorf("Data is not a string")
	}

	var err error
	x.Key, err = base64.RawURLEncoding.DecodeString(keydata)
	if err != nil {
		return err
	}

	if len(x.Key) != x.Bits/8 {
		return fmt.Errorf("Not enough key bits")
	}

	return nil

}

func (x *AESCBCSKCipher) Encrypt(data []byte) ([]byte, error) {

	block, err := aes.NewCipher(x.Key)
	if err != nil {
		return nil, err
	}

	msg := pad(data)
	ciphertext := make([]byte, aes.BlockSize+len(msg))

	iv := ciphertext[:aes.BlockSize]
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], msg)

	return ciphertext, nil

}

func (x *AESCBCSKCipher) Decrypt(data []byte) ([]byte, error) {

	if (len(data) % aes.BlockSize) != 0 {
		return nil, fmt.Errorf("Data must be multiple of blocksize")
	}

	block, err := aes.NewCipher(x.Key)
	if err != nil {
		return nil, err
	}

	iv := data[:aes.BlockSize]
	msg := data[aes.BlockSize:]

	dst := make([]byte, len(msg))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, msg)

	res, err := unpad(dst)
	if err != nil {
		return nil, err
	}

	return res, nil

}

func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func unpad(src []byte) ([]byte, error) {

	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, fmt.Errorf("Invalid padding")
	}

	return src[:(length - unpadding)], nil

}
