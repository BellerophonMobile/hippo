package hippo

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

// AlgorithmEd25519 is a constant string identifying the ed25519 algorithm.
const AlgorithmEd25519 = "ed25519"

func init() {
	err := RegisterCredentialer(&ed25519_v)
	if err != nil {
		panic(err)
	}
}

type ed25519_t struct{}

var ed25519_v ed25519_t

// Algorithm returns the label identifying the algorithm and
// parameterization of this credentialier.
func (x *ed25519_t) Algorithm() string {
	return AlgorithmEd25519
}

// Generate creates a new set of Credentials.
func (x *ed25519_t) Generate() (Credentials, error) {

	var credentials Ed25519Credentials
	var err error

	credentials.Public, credentials.Private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &credentials, nil

}

// New creates wraps the given keys as Credentials.
func (x *ed25519_t) New(public PublicKey, private PrivateKey) (Credentials, error) {

	var credentials Ed25519Credentials
	var err error

	err = credentials.SetPublicKey(public)
	if err != nil {
		return nil, err
	}

	err = credentials.SetPrivateKey(private)
	if err != nil {
		return nil, err
	}

	return &credentials, nil

}

// NewVerifier wraps the given PublicKey as Credentials.
func (x *ed25519_t) NewVerifier(key PublicKey) (Credentials, error) {

	var credentials Ed25519Credentials
	var err error

	err = credentials.SetPublicKey(key)
	if err != nil {
		return nil, err
	}

	return &credentials, nil

}

// NewSigner wraps the given PrivateKey as Credentials.
func (x *ed25519_t) NewSigner(key PrivateKey) (Credentials, error) {

	var credentials Ed25519Credentials
	var err error

	err = credentials.SetPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return &credentials, nil

}

// Ed25519Credentials are an actionable Ed25519 public/private key or
// matched pair.
type Ed25519Credentials struct {
	Private []byte
	Public  []byte
}

// PublicKey returns a JSON Base64-URL encoded marshaling of the
// credential's public key.
func (x *Ed25519Credentials) PublicKey() PublicKey {

	return PublicKey{
		Algorithm: AlgorithmEd25519,
		Public:    base64.URLEncoding.EncodeToString(x.Public[:]),
	}

}

// SetPublicKey sets the credential's public key from the given
// PublicKey containing JSON Base64-URL encoded data.
func (x *Ed25519Credentials) SetPublicKey(publickey PublicKey) error {

	if publickey.Algorithm != AlgorithmEd25519 {
		return fmt.Errorf("Algorithm mismatch %v vs %v", publickey.Algorithm, AlgorithmEd25519)
	}

	st, ok := publickey.Public.(string)
	if !ok {
		return ErrInvalidPublicKeyType
	}

	if len(st) != base64.URLEncoding.EncodedLen(ed25519.PublicKeySize) {
		return fmt.Errorf("Key data incorrect length")
	}

	bytes, err := base64.URLEncoding.DecodeString(st)
	if err != nil {
		return err
	}

	x.Public = bytes

	return nil

}

// SetPrivateKey sets the credential's public key from the given
// PrivateKey containing JSON Base64-URL encoded data.
func (x *Ed25519Credentials) SetPrivateKey(privatekey PrivateKey) error {

	if privatekey.Algorithm != AlgorithmEd25519 {
		return fmt.Errorf("Algorithm mismatch %v vs %v", privatekey.Algorithm, AlgorithmEd25519)
	}

	st, ok := privatekey.Private.(string)
	if !ok {
		return ErrInvalidPrivateKeyType
	}

	if len(st) != base64.URLEncoding.EncodedLen(ed25519.PrivateKeySize) {
		return fmt.Errorf("Key data incorrect length")
	}

	bytes, err := base64.URLEncoding.DecodeString(st)
	if err != nil {
		return err
	}

	x.Private = bytes

	return nil

}

// PrivateKey returns a JSON Base64-URL encoded marshaling of the
// credential's private key.
func (x *Ed25519Credentials) PrivateKey() PrivateKey {

	return PrivateKey{
		Algorithm: AlgorithmEd25519,
		Private:   base64.URLEncoding.EncodeToString(x.Private[:]),
	}

}

// Sign produces a signature for the given data.
func (x *Ed25519Credentials) Sign(data []byte) (Signature, error) {

	if x.Private == nil || len(x.Private) < ed25519.PrivateKeySize {
		return "", ErrNotSigner
	}

	sig := ed25519.Sign(x.Private, data)
	signature := base64.StdEncoding.EncodeToString(sig[:])

	return Signature(signature), nil

}

// Verify confirms that the given signature was produced from the
// given data using the private key associated with this credential's
// public key.
func (x *Ed25519Credentials) Verify(data []byte, signature Signature) error {

	if len(signature) != base64.StdEncoding.EncodedLen(ed25519.SignatureSize) {
		return fmt.Errorf("Signature incorrect length")
	}

	bytes, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return err
	}

	if !ed25519.Verify(x.Public, data, bytes) {
		return ErrUnverifiedSignature
	}

	return nil

}
