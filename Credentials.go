package hippo

import (
	"fmt"
)

var ErrNotSigner = fmt.Errorf("Not a signer")
var ErrInvalidPublicKeyType = fmt.Errorf("Invalid public key type")
var ErrInvalidPrivateKeyType = fmt.Errorf("Invalid private key type")
var ErrUnverifiedSignature = fmt.Errorf("Unverified signature")

// Verifier wraps a public key and can verify data.
type Verifier interface {
	PublicKey() PublicKey
	Verify(data []byte, signature Signature) error
}

// Signer wraps a private key and can sign data.
type Signer interface {
	PrivateKey() PrivateKey
	Sign(data []byte) (Signature, error)
}

// Credentials contain matched keys to both sign and verify data.
type Credentials interface {
	Verifier
	Signer

	SetPrivateKey(privatekey PrivateKey) error
	SetPublicKey(publickey PublicKey) error
}

// PublicKey is a structure for importing and exporting public
// keys. Verification is actually done with Credentials or a Verifier.
// The format of the data is defined by the algorithm implementation
// but should be generic JSON such that it may be parsed directly,
// i.e., without special knowledge of the value of Public as might be
// necessary to instantiate a specific class, etc..
type PublicKey struct {
	Algorithm string
	Public    interface{}
}

// ToFile serializes the PublicKey to the given file as JSON.
func (k PublicKey) ToFile(fn string) error {
	return toFile(k, fn)
}

// PrivateKey is a structure for importing and exporting private
// keys. Signing is actually done with Credentials or a Signer.  The
// format of the data is defined by the algorithm implementation but
// should be generic JSON such that it may be parsed directly, i.e.,
// without special knowledge of the value of Private as might be
// necessary to instantiate a specific class, etc..
type PrivateKey struct {
	Algorithm string
	Private   interface{}
}

// ToFile serializes the PrivateKey to the given file as JSON.
func (k PrivateKey) ToFile(fn string) error {
	return toFile(k, fn)
}

// A Signature is a padded Base64-Standard encoded strings.
type Signature string

// PublicKeyFromFile reads the entirety of the given file and attempts
// to parse it into a PublicKey.
func PublicKeyFromFile(fn string) (*PublicKey, error) {
	var key PublicKey
	err := fromFile(fn, &key)
	return &key, err
}

// PrivateKeyFromFile reads the entirety of the given file and
// attempts to parse it into a PrivateKey.
func PrivateKeyFromFile(fn string) (*PrivateKey, error) {
	var key PrivateKey
	err := fromFile(fn, &key)
	return &key, err
}
