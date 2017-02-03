package hippo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// AESMode captures the operational mode of the cipher.
type AESMode int

var modelabels = []string{
	"cbc",
	"gcm",
}

const (
	CBC AESMode = iota // Cipher block chaining mode.
	GCM                // Galois/counter mode.
)

// ErrUnsupportedMode is returned if a key is given that indicates a
// mode with no registered implementation.
var ErrUnsupportedMode = fmt.Errorf("Unknown mode")

// AlgorithmAES_256_CBC is a constant string identifying the AES
// algorithm with 256 bit key and cipher block chaining mode.
const AlgorithmAES_256_CBC = "aes-256-cbc"

// AlgorithmAES_256_CBC is a constant string identifying the AES
// algorithm with 256 bit key and Galois/counter mode.
const AlgorithmAES_256_GCM = "aes-256-gcm"

func init() {

	modes := []aes_t{
		aes_t{bits: 256, mode: CBC},
		aes_t{bits: 256, mode: GCM},
	}

	for _, m := range modes {
		err := RegisterSKCipherer(&m)
		if err != nil {
			panic(err)
		}
	}

}

type aes_t struct {
	bits int
	mode AESMode
}

// Algorithm returns the label identifying the algorithm and
// parameterization of this cipherer.
func (x *aes_t) Algorithm() string {
	return fmt.Sprintf("aes-%v-%v", x.bits, modelabels[x.mode])
}

// Generate creates a new SKCipher.
func (x *aes_t) Generate() (SKCipher, error) {

	var cipher AESCipher

	cipher.Algorithm = x.Algorithm()
	cipher.Bits = x.bits
	cipher.Mode = x.mode

	cipher.Key = make([]byte, x.bits/8)
	_, err := rand.Read(cipher.Key)
	if err != nil {
		return nil, err
	}

	return &cipher, nil

}

// New wraps the given secret key in an SKCipher.
func (x *aes_t) New(key PrivateKey) (SKCipher, error) {

	var cipher AESCipher
	var err error

	cipher.Algorithm = x.Algorithm()
	cipher.Bits = x.bits
	cipher.Mode = x.mode

	err = cipher.SetKey(key)
	if err != nil {
		return nil, err
	}

	return &cipher, nil

}

// An AESCipher is an actionable secret key.
type AESCipher struct {
	Algorithm string
	Bits      int
	Mode      AESMode
	Key       []byte
}

// SecretKey returns a JSON Base64-URL encoded marshaling of the
// cipher's secret key.
func (x *AESCipher) SecretKey() PrivateKey {

	key := PrivateKey{
		Algorithm: x.Algorithm,
		Private:   base64.RawURLEncoding.EncodeToString(x.Key),
	}

	return key

}

// SetKey sets the cipher's secret key from the given PrivateKey
// containing JSON Base64-URL encoded data.
func (x *AESCipher) SetKey(key PrivateKey) error {

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

// Encrypt produces cipherdata for the given plaindata.
func (x *AESCipher) Encrypt(data []byte) ([]byte, error) {

	block, err := aes.NewCipher(x.Key)
	if err != nil {
		return nil, err
	}

	switch x.Mode {
	case CBC:
		return encrypt_cbc(block, data)

	case GCM:
		return encrypt_gcm(block, data)
	}

	return nil, ErrUnsupportedMode

}

func encrypt_cbc(block cipher.Block, data []byte) ([]byte, error) {

	msg := pad(data)

	ciphertext := make([]byte, aes.BlockSize+len(msg))

	iv := ciphertext[:aes.BlockSize]
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], msg)

	return ciphertext, nil

}

func encrypt_gcm(block cipher.Block, data []byte) ([]byte, error) {

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, mode.NonceSize(), mode.NonceSize()+len(data))
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := mode.Seal(nonce, nonce, data, nil)

	return ciphertext, nil

}

// Decrypt takes cipherdata and produces plaindata.  N.B. that
// depending on the mode an invalid key or data may or may not
// generate an error.
func (x *AESCipher) Decrypt(data []byte) ([]byte, error) {

	block, err := aes.NewCipher(x.Key)
	if err != nil {
		return nil, err
	}

	switch x.Mode {
	case CBC:
		return decrypt_cbc(block, data)

	case GCM:
		return decrypt_gcm(block, data)
	}

	return nil, ErrUnsupportedMode

}

func decrypt_cbc(block cipher.Block, data []byte) ([]byte, error) {

	if (len(data) % aes.BlockSize) != 0 {
		return nil, fmt.Errorf("Data must be multiple of blocksize")
	}

	iv := data[:aes.BlockSize]
	msg := data[aes.BlockSize:]

	dst := make([]byte, len(msg))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, msg)

	plaintext, err := unpad(dst)
	if err != nil {
		return nil, err
	}

	return plaintext, nil

}

func decrypt_gcm(block cipher.Block, data []byte) ([]byte, error) {

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := data[:mode.NonceSize()]
	msg := data[mode.NonceSize():]

	plaintext, err := mode.Open(nil, nonce, msg, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil

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
