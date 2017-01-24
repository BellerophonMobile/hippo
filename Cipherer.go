package hippo

import (
	"sync"
)

// A Cipherer encapsulates key generation for a specific cipher
// algorithm and parameterization.
type Cipherer interface {
	// Algorithm returns the label identifying the algorithm and
	// parameterization of this Cipherer.
	Algorithm() string

	// Generate creates a new Cipher.
	Generate() (Cipher, error)

	// New wraps the given keys as a Cipher.
	New(public PublicKey, private PrivateKey) (Cipher, error)

	// NewEncrypter wraps the given PublicKey as a Cipher.
	NewEncrypter(key PublicKey) (Cipher, error)

	// NewDecrypter wraps the given PublicKey as a Cipher.
	NewDecrypter(key PrivateKey) (Cipher, error)
}

var cipherers = make(map[string]Cipherer)
var cipherersmutex sync.Mutex

// RegisterCipherer makes a Cipherer for a specific algorithm available
// through the uniform interface.
func RegisterCipherer(cipherer Cipherer) error {

	cipherersmutex.Lock()
	_, ok := cipherers[cipherer.Algorithm()]
	defer cipherersmutex.Unlock()

	if ok {
		return ErrPreviousAlgorithm
	}

	cipherers[cipherer.Algorithm()] = cipherer

	return nil

}

// GenerateCipher produces a Cipher with new random keys following the
// given algorithm.
func GenerateCipher(algorithm string) (Cipher, error) {

	cipherersmutex.Lock()
	cipherer, ok := cipherers[algorithm]
	cipherersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return cipherer.Generate()

}

// NewCipher creates a Cipher wrapping the given public and private
// key.  These must indicate the same algorithm but otherwise no test
// is made to confirm that they correspond to each other.
func NewCipher(public PublicKey, private PrivateKey) (Cipher, error) {

	if public.Algorithm != private.Algorithm {
		return nil, ErrAlgorithmMismatch
	}

	cipherersmutex.Lock()
	cipherer, ok := cipherers[public.Algorithm]
	cipherersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return cipherer.New(public, private)

}

// NewEncrypter wraps the given public key in a Cipher for use.
func NewEncrypter(key PublicKey) (Cipher, error) {

	cipherersmutex.Lock()
	cipherer, ok := cipherers[key.Algorithm]
	cipherersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return cipherer.NewEncrypter(key)

}

// NewDecrypter wraps the given private key in a Cipher for use.
func NewDecrypter(key PrivateKey) (Cipher, error) {

	cipherersmutex.Lock()
	cipherer, ok := cipherers[key.Algorithm]
	cipherersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return cipherer.NewDecrypter(key)

}
