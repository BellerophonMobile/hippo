package hippo

import (
	"sync"
)

// A PKCipherer encapsulates key generation for a specific public key
// encryption algorithm and parameterization.
type PKCipherer interface {
	// Algorithm returns the label identifying the algorithm and
	// parameterization of this PKCipherer.
	Algorithm() string

	// Generate creates a new PKCipher.
	Generate() (PKCipher, error)

	// New wraps the given keys as a PKCipher.
	New(public PublicKey, private PrivateKey) (PKCipher, error)

	// NewEncrypter wraps the given PublicKey as a PKCipher.
	NewEncrypter(key PublicKey) (PKCipher, error)

	// NewDecrypter wraps the given PublicKey as a PKCipher.
	NewDecrypter(key PrivateKey) (PKCipher, error)
}

var pkcipherers = make(map[string]PKCipherer)
var pkcipherersmutex sync.Mutex

// RegisterPKCipherer makes a PKCipherer for a specific algorithm available
// through the uniform interface.
func RegisterPKCipherer(cipherer PKCipherer) error {

	pkcipherersmutex.Lock()
	_, ok := pkcipherers[cipherer.Algorithm()]
	defer pkcipherersmutex.Unlock()

	if ok {
		return ErrPreviousAlgorithm
	}

	pkcipherers[cipherer.Algorithm()] = cipherer

	return nil

}

// GeneratePKCipher produces a PKCipher with new random keys following
// the given algorithm.
func GeneratePKCipher(algorithm string) (PKCipher, error) {

	pkcipherersmutex.Lock()
	cipherer, ok := pkcipherers[algorithm]
	pkcipherersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return cipherer.Generate()

}

// NewPKCipher creates a PKCipher wrapping the given public and
// private key.  These must indicate the same algorithm but otherwise
// no test is made to confirm that they correspond to each other.
func NewPKCipher(public PublicKey, private PrivateKey) (PKCipher, error) {

	if public.Algorithm != private.Algorithm {
		return nil, ErrAlgorithmMismatch
	}

	pkcipherersmutex.Lock()
	cipherer, ok := pkcipherers[public.Algorithm]
	pkcipherersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return cipherer.New(public, private)

}

// NewEncrypter wraps the given public key in a PKCipher for use.
func NewEncrypter(key PublicKey) (PKCipher, error) {

	pkcipherersmutex.Lock()
	cipherer, ok := pkcipherers[key.Algorithm]
	pkcipherersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return cipherer.NewEncrypter(key)

}

// NewDecrypter wraps the given private key in a PKCipher for use.
func NewDecrypter(key PrivateKey) (PKCipher, error) {

	pkcipherersmutex.Lock()
	cipherer, ok := pkcipherers[key.Algorithm]
	pkcipherersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return cipherer.NewDecrypter(key)

}
