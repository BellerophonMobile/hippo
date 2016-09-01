package hippo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Subject struct {
	ID        string
	PublicKey PublicKey
}

type Testament struct {
	ID string

	Subject Subject
	Claims  Claims

	Expires string
}

type Claims map[string]interface{}

type Declaration struct {
	Claim     string
	Signer    string
	Signature Signature
}

type Chain []*Declaration
type Certificate struct {
	Declarations Chain
}

func CertificateFromFile(fn string) (*Certificate, error) {

	var cert Certificate

	err := fromFile(fn, &cert)
	if err != nil {
		return nil, err
	}

	return IsValidCertificate(&cert)

}

func CertificateFromBytes(buf []byte) (*Certificate, error) {

	var cert Certificate

	err := fromBytes(buf, &cert)
	if err != nil {
		return nil, err
	}

	return IsValidCertificate(&cert)

}

func IsValidCertificate(cert *Certificate) (*Certificate, error) {

	if len(cert.Declarations) <= 0 {
		return nil, fmt.Errorf("No declarations in certificate")
	}

	return cert, nil

}

func (c *Certificate) ToFile(fn string) error {
	return toFile(c, fn)
}

func NewTestament(subjectID string, subjectkey PublicKey, claims Claims) *Testament {

	x := new(Testament)

	x.Subject.ID = subjectID

	x.Subject.PublicKey = subjectkey

	if claims == nil {
		x.Claims = make(Claims)
	} else {
		x.Claims = claims
	}

	return x

}

func UnpackTestament(b64 string) (*Testament, error) {

	bytes, err := base64.URLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	var testament Testament
	err = json.Unmarshal(bytes, &testament)
	if err != nil {
		return nil, err
	}

	return &testament, nil

}

func (x *Testament) Sign(id string, signer Signer) (*Declaration, error) {

	b64, err := x.Base64()
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign([]byte(b64))
	if err != nil {
		return nil, err
	}

	declaration := &Declaration{
		Claim:     b64,
		Signer:    id,
		Signature: signature,
	}

	return declaration, nil

}

func (x *Testament) Base64() (string, error) {

	j, err := json.Marshal(x)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(j), nil

}
