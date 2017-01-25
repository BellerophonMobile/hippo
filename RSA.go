package hippo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// AlgorithmRSA_OAEP is a constant string identifying the RSA
// algorithm with optimal asymmetric encryption padding.
const AlgorithmRSA_OAEP_2048 = "rsa-oaep-2048"

func init() {
	err := RegisterCipherer(&rsaoaep_t{bits: 2048})
	if err != nil {
		panic(err)
	}
}

type rsaoaep_t struct {
	bits int
}

// Algorithm returns the label identifying the algorithm and
// parameterization of this cipherer.
func (x *rsaoaep_t) Algorithm() string {
	return fmt.Sprintf("rsa-oaep-%v", x.bits)
}

// Generate creates a new Cipher.
func (x *rsaoaep_t) Generate() (Cipher, error) {

	var cipher RSAOAEPCipher
	var err error

	cipher.Algorithm = x.Algorithm()
	cipher.Bits = x.bits

	cipher.Private, err = rsa.GenerateKey(rand.Reader, x.bits)
	if err != nil {
		return nil, err
	}
	cipher.Public = &cipher.Private.PublicKey

	return &cipher, nil

}

// New wraps the given keys as Credentials.
func (x *rsaoaep_t) New(public PublicKey, private PrivateKey) (Cipher, error) {

	var cipher RSAOAEPCipher
	var err error

	cipher.Algorithm = x.Algorithm()
	cipher.Bits = x.bits

	err = cipher.SetPublicKey(public)
	if err != nil {
		return nil, err
	}

	err = cipher.SetPrivateKey(private)
	if err != nil {
		return nil, err
	}

	return &cipher, nil

}

// NewEncrypter wraps the given PublicKey as a Cipher.
func (x *rsaoaep_t) NewEncrypter(key PublicKey) (Cipher, error) {

	var cipher RSAOAEPCipher
	var err error

	cipher.Algorithm = x.Algorithm()
	cipher.Bits = x.bits

	err = cipher.SetPublicKey(key)
	if err != nil {
		return nil, err
	}

	return &cipher, nil

}

// NewDecrypter wraps the given PrivateKey as a Cipher.
func (x *rsaoaep_t) NewDecrypter(key PrivateKey) (Cipher, error) {

	var cipher RSAOAEPCipher
	var err error

	cipher.Algorithm = x.Algorithm()
	cipher.Bits = x.bits

	err = cipher.SetPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return &cipher, nil

}

type RSAOAEPCipher struct {
	Algorithm string
	Public    *rsa.PublicKey
	Private   *rsa.PrivateKey
	Bits      int
}

func (x *RSAOAEPCipher) PublicKey() PublicKey {

	bytelen := x.Bits / 8

	m := make(map[string]interface{})
	key := PublicKey{
		Algorithm: x.Algorithm,
		Public:    m,
	}

	setbigint(m, "N", x.Public.N, bytelen)
	setbigint(m, "E", big.NewInt(int64(x.Public.E)), bytelen)

	return key

}

func (x *RSAOAEPCipher) SetPublicKey(publickey PublicKey) error {

	if publickey.Algorithm != x.Algorithm {
		return ErrAlgorithmMismatch
	}

	bytelen := x.Bits / 8

	keydata, ok := publickey.Public.(map[string]interface{})
	if !ok {
		return fmt.Errorf("Data is not map")
	}

	var err error
	x.Public = &rsa.PublicKey{}

	x.Public.N, err = getbigint(keydata, "N", bytelen)
	if err != nil {
		return err
	}

	e, err := getbigint(keydata, "E", bytelen)
	if err != nil {
		return err
	}
	x.Public.E = int(e.Int64())

	return nil

}

func (x *RSAOAEPCipher) PrivateKey() PrivateKey {

	bytelen := x.Bits / 8

	m := make(map[string]interface{})
	key := PrivateKey{
		Algorithm: x.Algorithm,
		Private:   m,
	}

	setbigint(m, "N", x.Private.N, bytelen)
	setbigint(m, "D", x.Private.D, bytelen)
	setbigint(m, "Dp", x.Private.Precomputed.Dp, bytelen)
	setbigint(m, "Dq", x.Private.Precomputed.Dq, bytelen)
	setbigint(m, "Qi", x.Private.Precomputed.Qinv, bytelen)
	setbigint(m, "P", x.Private.Primes[0], bytelen)
	setbigint(m, "Q", x.Private.Primes[1], bytelen)
	setbigint(m, "E", big.NewInt(int64(x.Private.E)), bytelen)

	return key

}

func (x *RSAOAEPCipher) SetPrivateKey(privatekey PrivateKey) error {

	if privatekey.Algorithm != x.Algorithm {
		return ErrAlgorithmMismatch
	}

	bytelen := x.Bits / 8

	keydata, ok := privatekey.Private.(map[string]interface{})
	if !ok {
		return fmt.Errorf("Data is not map")
	}

	var err error
	x.Private = &rsa.PrivateKey{}

	x.Private.N, err = getbigint(keydata, "N", bytelen)
	if err != nil {
		return err
	}

	x.Private.D, err = getbigint(keydata, "D", bytelen)
	if err != nil {
		return err
	}

	x.Private.Precomputed.Dp, err = getbigint(keydata, "Dp", bytelen)
	if err != nil {
		return err
	}

	x.Private.Precomputed.Dq, err = getbigint(keydata, "Dq", bytelen)
	if err != nil {
		return err
	}

	x.Private.Precomputed.Qinv, err = getbigint(keydata, "Qi", bytelen)
	if err != nil {
		return err
	}

	x.Private.Primes = make([]*big.Int, 2)
	if err != nil {
		return err
	}

	x.Private.Primes[0], err = getbigint(keydata, "P", bytelen)
	if err != nil {
		return err
	}

	x.Private.Primes[1], err = getbigint(keydata, "Q", bytelen)
	if err != nil {
		return err
	}

	e, err := getbigint(keydata, "E", bytelen)
	if err != nil {
		return err
	}
	x.Private.E = int(e.Int64())

	return nil

}

func (x *RSAOAEPCipher) Encrypt(data []byte) ([]byte, error) {

	return rsa.EncryptOAEP(sha256.New(), rand.Reader, x.Public, data, []byte{})

}

func (x *RSAOAEPCipher) Decrypt(data []byte) ([]byte, error) {

	return rsa.DecryptOAEP(sha256.New(), rand.Reader, x.Private, data, []byte{})

}
