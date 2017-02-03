package hippo

import (
	"fmt"
)

// ErrNotEncrypter is returned when attempting to encrypt data without
// a private key, or if a PKCipher does not implement encryption.
var ErrNotEncrypter = fmt.Errorf("Not an encrypter")

// ErrNotDecrypter is returned when attempting to decrypt data without
// a public key, or if a PKCipher does not implement encryption.
var ErrNotDecrypter = fmt.Errorf("Not a decrypter")

// Encrypter wraps a public key and encrypts data.
type Encrypter interface {

	// PublicKey returns a JSON Base64-URL encoded marshaling of the
	// Encrypter's public key.
	PublicKey() PublicKey

	// Encrypt produces cipherdata for the given plaindata.
	Encrypt(data []byte) ([]byte, error)
}

// Decrypter wraps a private key and decrypt datas.
type Decrypter interface {

	// PrivateKey returns a JSON Base64-URL encoded marshaling of the
	// Decrypter's private key.
	PrivateKey() PrivateKey

	// Decrypt takes cipherdata and produces plaindata.  N.B.: In
	// general the absence of an error does NOT indicate that the data
	// is valid.  Under a public key algorithm this question doesn't
	// even make sense in terms of an attack.  A separate mechanism must
	// be applied to assure integrity and authenticity.  Then note that
	// implementing such a mechanism is not as simple as signing either
	// the plaindata or cipherdata alone.
	Decrypt(data []byte) ([]byte, error)
}

// PKCiphers encapsulate a public key (asymmetric) encryption
// algorithm, parameterization, and matched keys to encrypt and
// decrypt data.
type PKCipher interface {
	Encrypter
	Decrypter

	// SetPrivateKey sets the PKCipher's public key from the given
	// PrivateKey containing JSON Base64-URL encoded data.
	SetPrivateKey(privatekey PrivateKey) error

	// SetPublicKey sets the PKCipher's public key from the given
	// PublicKey containing JSON Base64-URL encoded data.
	SetPublicKey(publickey PublicKey) error
}
