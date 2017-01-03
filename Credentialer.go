package hippo

import (
	"fmt"
	"sync"
)

// ErrPreviousAlgorithm is returned by Register calls when registering a
// duplicate credentialier.
var ErrPreviousAlgorithm = fmt.Errorf("Previous algorithm registration")

// ErrUnknownAlgorithm is returned when attempting to generate or load keys
// from an unregistered algorithm.
var ErrUnknownAlgorithm = fmt.Errorf("Unknown algorithm")

// ErrAlgorithmMismatch is returned when generating credentials from a keypair
// with different algorithms specified.
var ErrAlgorithmMismatch = fmt.Errorf("Algorithm mismatch")

// A Credentialer encapsulates key generation for a specific algorithm
// and parameterization.
type Credentialer interface {
	// Algorithm returns the label identifying the algorithm and
	// parameterization of this credentialier.
	Algorithm() string

	// Generate creates a new set of Credentials.
	Generate() (Credentials, error)

	// New wraps the given keys as Credentials.
	New(public PublicKey, private PrivateKey) (Credentials, error)

	// NewVerifier wraps the given PublicKey as Credentials.
	NewVerifier(key PublicKey) (Credentials, error)

	// NewSigner wraps the given PublicKey as Credentials.
	NewSigner(key PrivateKey) (Credentials, error)
}

var credentialers = make(map[string]Credentialer)
var credentialersmutex sync.Mutex

// Register makes a Credentialer for a specific algorithm available
// through the uniform interface.
func Register(credentialer Credentialer) error {

	credentialersmutex.Lock()
	_, ok := credentialers[credentialer.Algorithm()]
	defer credentialersmutex.Unlock()

	if ok {
		return ErrPreviousAlgorithm
	}

	credentialers[credentialer.Algorithm()] = credentialer

	return nil

}

// Generate produces Credentials with new random keys following the
// given algorithm.
func Generate(algorithm string) (Credentials, error) {

	credentialersmutex.Lock()
	credentialer, ok := credentialers[algorithm]
	credentialersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return credentialer.Generate()

}

// New creates Credentials wrapping the given public and private key.
// These must indicate the same algorithm but otherwise no test is
// made to confirm that they correspond to each other.
func New(public PublicKey, private PrivateKey) (Credentials, error) {

	if public.Algorithm != private.Algorithm {
		return nil, ErrAlgorithmMismatch
	}

	credentialersmutex.Lock()
	credentialer, ok := credentialers[public.Algorithm]
	credentialersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return credentialer.New(public, private)

}

// NewVerifier wraps the given public key in Credentials for use.
func NewVerifier(key PublicKey) (Credentials, error) {

	credentialersmutex.Lock()
	credentialer, ok := credentialers[key.Algorithm]
	credentialersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return credentialer.NewVerifier(key)

}

// NewSigner wraps the given private key in Credentials for use.
func NewSigner(key PrivateKey) (Credentials, error) {

	credentialersmutex.Lock()
	credentialer, ok := credentialers[key.Algorithm]
	credentialersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return credentialer.NewSigner(key)

}
