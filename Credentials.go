package hippo

import (
	"fmt"
)

// ErrNotSigner is returned when attempting to sign data without a
// private key or if the algorithm interface does not implement
// signing.
var ErrNotSigner = fmt.Errorf("Not a signer")

// ErrNotVerifier is returned when attempting to verify data without a
// public key or if the algorithm interface does not implement
// verification.
var ErrNotVerifier = fmt.Errorf("Not a verifier")

// ErrUnverifiedSignature is returned when a signature fails validation.
var ErrUnverifiedSignature = fmt.Errorf("Unverified signature")

// Verifier wraps a public key and can verify data.
type Verifier interface {
	// PublicKey returns a JSON Base64-URL encoded marshaling of the
	// credential's public key.
	PublicKey() PublicKey

	// Verify confirms that the given signature was produced from the
	// given data using the private key associated with this
	// credential's public key.  Any error indicates that it was not.
	Verify(data []byte, signature Signature) error
}

// Signer wraps a private key and can sign data.
type Signer interface {
	// PrivateKey returns a JSON Base64-URL encoded marshaling of the
	// credential's private key.
	PrivateKey() PrivateKey

	// Sign produces a signature for the given data.
	Sign(data []byte) (Signature, error)
}

// Credentials contain matched keys to both sign and verify data.
type Credentials interface {
	Verifier
	Signer

	// SetPrivateKey sets the credential's public key from the given
	// PrivateKey containing JSON Base64-URL encoded data.
	SetPrivateKey(privatekey PrivateKey) error

	// SetPublicKey sets the credential's public key from the given
	// PublicKey containing JSON Base64-URL encoded data.
	SetPublicKey(publickey PublicKey) error
}

// A Signature is a padded Base64-Standard encoded strings.
type Signature string
