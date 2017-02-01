package hippo

import (
	"fmt"
)

// ErrInvalidPrivateKeyType is returned when setting an invalid
// private key to Credentials or Ciphers.
var ErrInvalidPrivateKeyType = fmt.Errorf("Invalid private key type")

// PrivateKey is a structure for importing and exporting private
// keys. Signing is actually done with Credentials or a Signer.
// Encryption is done with a Cipher or an Encrypter.  The format of
// the data is defined by the algorithm implementation but should be
// generic JSON such that it may be parsed directly, i.e., without
// special knowledge of the value of Private as might be necessary to
// instantiate a specific class, etc..
type PrivateKey struct {
	Algorithm string
	Private   interface{}
}

// ToFile serializes the PrivateKey to the given file as JSON.
func (k PrivateKey) ToFile(fn string) error {
	return toFile(k, fn)
}

// PrivateKeyFromFile reads the entirety of the given file and
// attempts to parse it into a PrivateKey.
func PrivateKeyFromFile(fn string) (*PrivateKey, error) {
	var key PrivateKey
	err := fromFile(fn, &key)
	return &key, err
}

func (k PrivateKey) ToBytes() ([]byte,error) {
	return toBytes(k)
}

func PrivateKeyFromBytes(buf []byte) (*PrivateKey,error) {
	var key PrivateKey
	err := fromBytes(buf, &key)
	return &key, err
}
