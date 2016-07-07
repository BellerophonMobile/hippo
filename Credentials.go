package hippo

import (
	"io/ioutil"
	"encoding/json"
)

// Verifier wraps a public key and can verify data.
type Verifier interface {
	PublicKey() PublicKey
	Verify(data []byte, signature Signature) error
}

// Signer wraps a private key and can sign data.
type Signer interface {
	PrivateKey() PrivateKey	
	Sign(data []byte) (Signature,error)
}

// Credentials contain matched keys to both sign and verify data.
type Credentials interface {
	Verifier
	Signer

	SetPrivateKey(privatekey PrivateKey) error
	SetPublicKey(publickey PublicKey) error
}

// PublicKey is a structure for importing and exporting public
// keys. Verification is actually done with Credentials.or a Verifier.
// The format of the data is defined by the algorithm implementation
// but should be generic JSON such that it may be parsed directly,
// i.e., without special knowledge of the value of Public as might be
// necessary to instantiate a specific class, etc..
type PublicKey struct {
	Algorithm string
	Public interface{}
}

// PrivateKey is a structure for importing and exporting private
// keys. Signing is actually done with Credentials.or a Signer.  The
// format of the data is defined by the algorithm implementation but
// should be generic JSON such that it may be parsed directly, i.e.,
// without special knowledge of the value of Private as might be
// necessary to instantiate a specific class, etc..
type PrivateKey struct {
	Algorithm string
	Private interface{}
}

// Signatures are padded Base64 standard encoded strings.
type Signature string


// PublicKeyFromFile reads the entirety of the given file and attempts
// to parse it into a PublicKey.
func PublicKeyFromFile(fn string) (*PublicKey,error) {

	bits,err := ioutil.ReadFile(fn)
	if err != nil {
		return nil,err
	}

	var key PublicKey

	err = json.Unmarshal(bits, &key)
	if err != nil {
		return nil,err
	}

	return &key,nil

}

// PrivateKeyFromFile reads the entirety of the given file and
// attempts to parse it into a PrivateKey.
func PrivateKeyFromFile(fn string) (*PrivateKey,error) {

	bits,err := ioutil.ReadFile(fn)
	if err != nil {
		return nil,err
	}

	var key PrivateKey

	err = json.Unmarshal(bits, &key)
	if err != nil {
		return nil,err
	}

	return &key,nil

}
