package hippo

import (
	"sync"
)

// An SKCipherer encapsulates key generation for a specific secret key
// (symmetric) encryption algorithm and parameterization.
type SKCipherer interface {

	// Algorithm returns the label identifying the algorithm and
	// parameterization of this SKCipherer.
	Algorithm() string

	// Generate creates a new SKCipher.
	Generate() (SKCipher, error)

	// New wraps the given secret key as an SKCipher.
	New(key PrivateKey) (SKCipher, error)

}

var skcipherers = make(map[string]SKCipherer)
var skcipherersmutex sync.Mutex

// RegisterSKCipherer makes a SKCipherer for a specific algorithm
// available through the uniform interface.
func RegisterSKCipherer(cipherer SKCipherer) error {

	skcipherersmutex.Lock()
	_, ok := skcipherers[cipherer.Algorithm()]
	defer skcipherersmutex.Unlock()

	if ok {
		return ErrPreviousAlgorithm
	}

	skcipherers[cipherer.Algorithm()] = cipherer

	return nil

}

// GenerateSKCipher produces a SKCipher with a new random key
// following the given algorithm.
func GenerateSKCipher(algorithm string) (SKCipher, error) {

	skcipherersmutex.Lock()
	cipherer, ok := skcipherers[algorithm]
	skcipherersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return cipherer.Generate()

}

// NewSKCipher creates a SKCipher wrapping the given secret key.
func NewSKCipher(key PrivateKey) (SKCipher, error) {

	skcipherersmutex.Lock()
	cipherer, ok := skcipherers[key.Algorithm]
	skcipherersmutex.Unlock()

	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	return cipherer.New(key)

}
