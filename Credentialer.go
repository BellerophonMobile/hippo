package hippo

import (
	"fmt"
	"sync"
)

var PreviousAlgorithm           = fmt.Errorf("Previous algorithm registration")
var UnknownAlgorithm            = fmt.Errorf("Unknown algorithm")
var AlgorithmMismatch           = fmt.Errorf("Algorithm mismatch")

var NotSigner                   = fmt.Errorf("Not a signer")

var InvalidPublicKeyType        = fmt.Errorf("Invalid public key type")

var InvalidPrivateKeyType       = fmt.Errorf("Invalid private key type")

var InvalidSignatureType        = fmt.Errorf("Invalid signature")
var UnverifiedSignature         = fmt.Errorf("Unverified signature")

// A Credentialer encapsulates key generation for a specific algorithm.
type Credentialer interface {
	Algorithm() string

	Generate() (Credentials,error)
	New(public PublicKey, private PrivateKey) (Credentials,error)
	NewVerifier(key PublicKey) (Credentials,error)
	NewSigner(key PrivateKey) (Credentials,error)
}

var credentialers = make(map[string]Credentialer)
var credentialersmutex sync.Mutex

// Register makes a Credentialer for a specific algorithm available through
// the uniform interface
func Register(credentialer Credentialer) error {

	credentialersmutex.Lock()
	_,ok := credentialers[credentialer.Algorithm()]
	defer credentialersmutex.Unlock()
	
	if ok {
		return PreviousAlgorithm
	}
	
	credentialers[credentialer.Algorithm()] = credentialer

	return nil

}

// Generate produces Credentials with new random keys following the
// given algorithm.
func Generate(algorithm string) (Credentials,error) {

	credentialersmutex.Lock()
	credentialer,ok := credentialers[algorithm]
	credentialersmutex.Unlock()

	if !ok {
		return nil,UnknownAlgorithm
	}

	return credentialer.Generate()

}

// New creates Credentials wrapping the given public and private key.
// These must be matched.
func New(public PublicKey, private PrivateKey) (Credentials,error) {

	if public.Algorithm != private.Algorithm {
		return nil,AlgorithmMismatch
	}
	
	credentialersmutex.Lock()
	credentialer,ok := credentialers[public.Algorithm]
	credentialersmutex.Unlock()

	if !ok {
		return nil,UnknownAlgorithm
	}

	return credentialer.New(public, private)

}

// NewVerifier wraps the given public key in Credentials.
func NewVerifier(key PublicKey) (Credentials,error) {

	credentialersmutex.Lock()
	credentialer,ok := credentialers[key.Algorithm]
	credentialersmutex.Unlock()

	if !ok {
		return nil,UnknownAlgorithm
	}

	return credentialer.NewVerifier(key)

}

// NewSigner wraps the given private key in Credentials.
func NewSigner(key PrivateKey) (Credentials,error) {

	credentialersmutex.Lock()
	credentialer,ok := credentialers[key.Algorithm]
	credentialersmutex.Unlock()

	if !ok {
		return nil,UnknownAlgorithm
	}

	return credentialer.NewSigner(key)

}
