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
		ecdsa_t{
			label: "p256",
			curve: elliptic.P256(),
		},
	}
	for _, c := range curves {
		Register(&c)
	}

}

type ecdsa_t struct {
	label string
	curve elliptic.Curve
}

func (x *ecdsa_t) Algorithm() string {
	return "ecdsa-" + x.label
}

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

type ECDSACredentials struct {
	Algorithm string
	Curve     elliptic.Curve
	Public    *ecdsa.PublicKey
	Private   *ecdsa.PrivateKey
}

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

func (x *ECDSACredentials) SetPublicKey(publickey PublicKey) error {

	if publickey.Algorithm != x.Algorithm {
		return AlgorithmMismatch
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
		x.Curve,
		&xx,
		&xy,
	}

	return nil

}

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

func (x *ECDSACredentials) SetPrivateKey(privatekey PrivateKey) error {

	if privatekey.Algorithm != x.Algorithm {
		return AlgorithmMismatch
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
		ecdsa.PublicKey{
			x.Curve,
			&xx,
			&xy,
		},
		&xd,
	}

	return nil

}

func (x *ECDSACredentials) Sign(data []byte) (Signature, error) {

	if x.Private == nil {
		return "", NotSigner
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

func (x *ECDSACredentials) Verify(data []byte, signature Signature) error {

	/*
		st,ok := signature.Signature.(string)
		if !ok {
			return InvalidSignatureType
		}
	*/

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
		return UnverifiedSignature
	}

	return nil

}
