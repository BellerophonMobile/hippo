package hippo

import (
	"fmt"
)

// ErrNotEncrypter is returned when attempting to encrypt data without
// a private key, or if the algorithm interface does not implement
// encryption.
var ErrNotEncrypter = fmt.Errorf("Not an encrypter")

// ErrNotDecrypter is returned when attempting to decrypt data without
// a public key, or if the algorithm interface does not implement
// encryption.
var ErrNotDecrypter = fmt.Errorf("Not a decrypter")

// ErrSymmetric is returned when public key operations are called on a
// symmetric algorithm.
var ErrSymmetric = fmt.Errorf("Algorithm is symmetric, no public key")

// Encrypter wraps a public key and can encrypt data.
type Encrypter interface {
	// PublicKey returns a JSON Base64-URL encoded marshaling of the
	// encrypter's public key.
	PublicKey() PublicKey

	// Encrypt produces a cipher block for the given data.
	Encrypt(data []byte) ([]byte, error)
}

// Decrypter wraps a private key and can decrypt data.
type Decrypter interface {
	// PrivateKey returns a JSON Base64-URL encoded marshaling of the
	// decrypter's private key.
	PrivateKey() PrivateKey

	// Decrypt takes a cipher block and produces clear data.  N.B.: In
	// general the absence of an error does NOT indicate that the data
	// is valid.  Indeed, under a public key algorithm this question
	// doesn't even make sense.  A separate mechanism must be applied.
	// Then note that this is not as simple as signing either the
	// plaintext or ciphertext alone.
	Decrypt(data []byte) ([]byte, error)
}

// Ciphers contain matched keys to both encrypt and decrypt data.
type Cipher interface {
	Encrypter
	Decrypter

	// SetPrivateKey sets the cipher's public key from the given
	// PrivateKey containing JSON Base64-URL encoded data.
	SetPrivateKey(privatekey PrivateKey) error

	// SetPublicKey sets the cipher's public key from the given
	// PublicKey containing JSON Base64-URL encoded data.
	SetPublicKey(publickey PublicKey) error
}
