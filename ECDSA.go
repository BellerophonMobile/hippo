package hippo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

var AlgorithmECDSA_P256 = "ecdsa-p256"

func init() {

	curves := []ecdsa_t{
		{
			label: "p256",
			curve: elliptic.P256(),
		},
	}
	for _, c := range curves {
		err := Register(&c)
		if err != nil {
			panic(err)
		}
	}

}

type ecdsa_t struct {
	label string
	curve elliptic.Curve
}

// Algorithm returns the label identifying the algorithm and
// parameterization of this credentialier.
func (x *ecdsa_t) Algorithm() string {
	return "ecdsa-" + x.label
}

// Generate creates a new set of Credentials.
func (x *ecdsa_t) Generate() (Credentials, error) {

	var credentials ECDSACredentials
	var err error

	credentials.Algorithm = x.Algorithm()
	credentials.Curve = x.curve

	credentials.Private, err = ecdsa.GenerateKey(x.curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	credentials.Public = &credentials.Private.PublicKey

	return &credentials, nil

}

// New creates wraps the given keys as Credentials.
func (x *ecdsa_t) New(public PublicKey, private PrivateKey) (Credentials, error) {

	var credentials ECDSACredentials
	var err error

	credentials.Algorithm = x.Algorithm()
	credentials.Curve = x.curve

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
func (x *ecdsa_t) NewVerifier(key PublicKey) (Credentials, error) {

	var credentials ECDSACredentials
	var err error

	credentials.Algorithm = x.Algorithm()
	credentials.Curve = x.curve

	err = credentials.SetPublicKey(key)
	if err != nil {
		return nil, err
	}

	return &credentials, nil

}

// NewSigner wraps the given PublicKey as Credentials.
func (x *ecdsa_t) NewSigner(key PrivateKey) (Credentials, error) {

	var credentials ECDSACredentials
	var err error

	credentials.Algorithm = x.Algorithm()
	credentials.Curve = x.curve

	err = credentials.SetPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return &credentials, nil

}

// ECDSACredentials are an actionable ECDSA public/private key or
// matched pair.
type ECDSACredentials struct {
	Algorithm string
	Curve     elliptic.Curve
	Public    *ecdsa.PublicKey
	Private   *ecdsa.PrivateKey
}

// PublicKey returns a JSON Base64-URL encoded marshaling of the
// credential's public key.
func (x *ECDSACredentials) PublicKey() PublicKey {

	bitlen := x.Curve.Params().BitSize / 8

	data := x.Public.X.Bytes()
	pad := make([]byte, bitlen-len(data))
	xbytes := append(pad, data...)

	data = x.Public.Y.Bytes()
	pad = make([]byte, bitlen-len(data))
	ybytes := append(pad, data...)

	return PublicKey{
		Algorithm: x.Algorithm,
		Public: map[string]interface{}{
			"X": base64.RawURLEncoding.EncodeToString(xbytes),
			"Y": base64.RawURLEncoding.EncodeToString(ybytes),
		},
	}

}

// SetPublicKey sets the credential's public key from the given
// PublicKey containing JSON Base64-URL encoded data.
func (x *ECDSACredentials) SetPublicKey(publickey PublicKey) error {

	if publickey.Algorithm != x.Algorithm {
		return ErrAlgorithmMismatch
	}

	bitlen := x.Curve.Params().BitSize / 8

	pubdata, ok := publickey.Public.(map[string]interface{})
	if !ok {
		return fmt.Errorf("Data is not map")
	}

	ival, ok := pubdata["X"]
	if !ok {
		return fmt.Errorf("Missing X component")
	}

	sval, ok := ival.(string)
	if !ok {
		return fmt.Errorf("X component is not string")
	}

	b, err := base64.RawURLEncoding.DecodeString(sval)
	if err != nil {
		return err
	}

	if len(b) != bitlen {
		return fmt.Errorf("Incorrect bit length")
	}

	var xx big.Int
	xx.SetBytes(b)

	ival, ok = pubdata["Y"]
	if !ok {
		return fmt.Errorf("Missing Y component")
	}

	sval, ok = ival.(string)
	if !ok {
		return fmt.Errorf("Y component is not string")
	}

	b, err = base64.RawURLEncoding.DecodeString(sval)
	if err != nil {
		return err
	}

	if len(b) != bitlen {
		return fmt.Errorf("Incorrect bit length")
	}

	var xy big.Int
	xy.SetBytes(b)

	x.Public = &ecdsa.PublicKey{
		Curve: x.Curve,
		X:     &xx,
		Y:     &xy,
	}

	return nil

}

// PrivateKey returns a JSON Base64-URL encoded marshaling of the
// credential's private key.
func (x *ECDSACredentials) PrivateKey() PrivateKey {

	bitlen := x.Curve.Params().BitSize / 8

	data := x.Public.X.Bytes()
	pad := make([]byte, bitlen-len(data))
	xbytes := append(pad, data...)

	data = x.Public.Y.Bytes()
	pad = make([]byte, bitlen-len(data))
	ybytes := append(pad, data...)

	data = x.Private.D.Bytes()
	pad = make([]byte, bitlen-len(data))
	dbytes := append(pad, data...)

	return PrivateKey{
		Algorithm: x.Algorithm,
		Private: map[string]interface{}{
			"X": base64.RawURLEncoding.EncodeToString(xbytes),
			"Y": base64.RawURLEncoding.EncodeToString(ybytes),
			"D": base64.RawURLEncoding.EncodeToString(dbytes),
		},
	}

}

// SetPrivateKey sets the credential's public key from the given
// PrivateKey containing JSON Base64-URL encoded data.
func (x *ECDSACredentials) SetPrivateKey(privatekey PrivateKey) error {

	if privatekey.Algorithm != x.Algorithm {
		return ErrAlgorithmMismatch
	}

	bitlen := x.Curve.Params().BitSize / 8

	keydata, ok := privatekey.Private.(map[string]interface{})
	if !ok {
		return fmt.Errorf("Data is not map")
	}

	ival, ok := keydata["X"]
	if !ok {
		return fmt.Errorf("Missing X component")
	}

	sval, ok := ival.(string)
	if !ok {
		return fmt.Errorf("X component is not string")
	}

	b, err := base64.RawURLEncoding.DecodeString(sval)
	if err != nil {
		return err
	}

	if len(b) != bitlen {
		return fmt.Errorf("Incorrect bit length")
	}

	var xx big.Int
	xx.SetBytes(b)

	ival, ok = keydata["Y"]
	if !ok {
		return fmt.Errorf("Missing Y component")
	}

	sval, ok = ival.(string)
	if !ok {
		return fmt.Errorf("Y component is not string")
	}

	b, err = base64.RawURLEncoding.DecodeString(sval)
	if err != nil {
		return err
	}
	if len(b) != bitlen {
		return fmt.Errorf("Incorrect bit length")
	}

	var xy big.Int
	xy.SetBytes(b)

	ival, ok = keydata["D"]
	if !ok {
		return fmt.Errorf("Missing D component")
	}

	sval, ok = ival.(string)
	if !ok {
		return fmt.Errorf("D component is not string")
	}

	b, err = base64.RawURLEncoding.DecodeString(sval)
	if err != nil {
		return err
	}
	if len(b) != bitlen {
		return fmt.Errorf("Incorrect bit length")
	}
	var xd big.Int
	xd.SetBytes(b)

	x.Private = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: x.Curve,
			X:     &xx,
			Y:     &xy,
		},
		D: &xd,
	}

	return nil

}

// Sign produces a signature for the given data.
func (x *ECDSACredentials) Sign(data []byte) (Signature, error) {

	if x.Private == nil {
		return "", ErrNotSigner
	}

	hasher := sha256.New()
	hasher.Write(data)
	sum := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, x.Private, sum)
	if err != nil {
		return "", err
	}

	bitlen := x.Curve.Params().BitSize / 8

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, bitlen)
	copy(rBytesPadded[bitlen-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, bitlen)
	copy(sBytesPadded[bitlen-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	signature := base64.StdEncoding.EncodeToString(out)

	return Signature(signature), nil

}

// Verify confirms that the given signature was produced from the
// given data using the private key associated with this credential's
// public key.
func (x *ECDSACredentials) Verify(data []byte, signature Signature) error {

	bytes, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return err
	}

	bitlen := x.Curve.Params().BitSize / 8

	if len(bytes) != bitlen*2 {
		return fmt.Errorf("Incorrect signature byte length")
	}

	r := big.NewInt(0).SetBytes(bytes[:bitlen])
	s := big.NewInt(0).SetBytes(bytes[bitlen:])

	hasher := sha256.New()
	hasher.Write(data)
	sum := hasher.Sum(nil)

	if !ecdsa.Verify(x.Public, sum, r, s) {
		return ErrUnverifiedSignature
	}

	return nil

}
