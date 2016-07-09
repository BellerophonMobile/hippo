package hippo

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/agl/ed25519"
)

var AlgorithmEd25519 = "ed25519"

func init() {
	Register(&ed25519_v)
}

type ed25519_t struct {
}

var ed25519_v ed25519_t

func (x *ed25519_t) Algorithm() string {
	return AlgorithmEd25519
}

func (x *ed25519_t) Generate() (Credentials, error) {

	var credentials Ed25519Credentials
	var err error

	credentials.Public, credentials.Private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &credentials, nil

}

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

func (x *ed25519_t) NewVerifier(key PublicKey) (Credentials, error) {

	var credentials Ed25519Credentials
	var err error

	err = credentials.SetPublicKey(key)
	if err != nil {
		return nil, err
	}

	return &credentials, nil

}

func (x *ed25519_t) NewSigner(key PrivateKey) (Credentials, error) {

	var credentials Ed25519Credentials
	var err error

	err = credentials.SetPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return &credentials, nil

}

type Ed25519Credentials struct {
	Private *[ed25519.PrivateKeySize]byte
	Public  *[ed25519.PublicKeySize]byte
}

func (x *Ed25519Credentials) SetPublicKey(publickey PublicKey) error {

	if publickey.Algorithm != AlgorithmEd25519 {
		return AlgorithmMismatch
	}

	st, ok := publickey.Public.(string)
	if !ok {
		return InvalidPublicKeyType
	}

	if len(st) != base64.URLEncoding.EncodedLen(ed25519.PublicKeySize) {
		return fmt.Errorf("Key data incorrect length")
	}

	bytes, err := base64.URLEncoding.DecodeString(st)
	if err != nil {
		return err
	}

	var key [ed25519.PublicKeySize]byte
	copy(key[:], bytes)
	x.Public = &key

	return nil

}

func (x *Ed25519Credentials) SetPrivateKey(privatekey PrivateKey) error {

	if privatekey.Algorithm != AlgorithmEd25519 {
		return AlgorithmMismatch
	}

	st, ok := privatekey.Private.(string)
	if !ok {
		return InvalidPrivateKeyType
	}

	if len(st) != base64.URLEncoding.EncodedLen(ed25519.PrivateKeySize) {
		return fmt.Errorf("Key data incorrect length")
	}

	bytes, err := base64.URLEncoding.DecodeString(st)
	if err != nil {
		return err
	}

	var key [ed25519.PrivateKeySize]byte
	copy(key[:], bytes)
	x.Private = &key

	return nil

}

func (x *Ed25519Credentials) PublicKey() PublicKey {

	return PublicKey{
		Algorithm: AlgorithmEd25519,
		Public:    base64.URLEncoding.EncodeToString(x.Public[:]),
	}

}

func (x *Ed25519Credentials) PrivateKey() PrivateKey {

	return PrivateKey{
		Algorithm: AlgorithmEd25519,
		Private:   base64.URLEncoding.EncodeToString(x.Private[:]),
	}

}

func (x *Ed25519Credentials) Sign(data []byte) (Signature, error) {

	if x.Private == nil || len(x.Private) < ed25519.PrivateKeySize {
		return "", NotSigner
	}

	sig := ed25519.Sign(x.Private, data)
	signature := base64.StdEncoding.EncodeToString(sig[:])

	return Signature(signature), nil

}

func (x *Ed25519Credentials) Verify(data []byte, signature Signature) error {

	/*
		st,ok := signature.Signature.(string)
		if !ok {
			return InvalidSignatureType
		}
	*/

	if len(signature) != base64.StdEncoding.EncodedLen(ed25519.SignatureSize) {
		return fmt.Errorf("Signature incorrect length")
	}

	bytes, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return err
	}

	var sig [ed25519.SignatureSize]byte
	copy(sig[:], bytes)

	if !ed25519.Verify(x.Public, data, &sig) {
		return UnverifiedSignature
	}

	return nil

}
