package hippo

import (
	"fmt"
)

// ErrInvalidPublicKeyType is returned when setting an invalid public
// key to Credentials or Ciphers.
var ErrInvalidPublicKeyType = fmt.Errorf("Invalid public key type")

// PublicKey is a structure for importing and exporting public
// keys. Verification is actually done with Credentials or a Verifier.
// Decryption is actually done with a Cipher or a Decrypter.  The
// format of the data is defined by the algorithm implementation but
// should be generic JSON such that it may be parsed directly, i.e.,
// without special knowledge of the value of Public as might be
// necessary to instantiate a specific class, etc..
type PublicKey struct {
	Algorithm string
	Public    interface{}
}

// ToFile serializes the PublicKey to the given file as JSON.
func (k PublicKey) ToFile(fn string) error {
	return toFile(k, fn)
}

// PublicKeyFromFile reads the entirety of the given file and attempts
// to parse it into a PublicKey.
func PublicKeyFromFile(fn string) (*PublicKey, error) {
	var key PublicKey
	err := fromFile(fn, &key)
	return &key, err
}

// ToBytes marshals the key to a byte array.
func (k PublicKey) ToBytes() ([]byte, error) {
	return toBytes(k)
}

// PublicKeyFromBytes unmarshals a key from the given byte array.
func PublicKeyFromBytes(buf []byte) (*PublicKey, error) {
	var key PublicKey
	err := fromBytes(buf, &key)
	return &key, err
}
