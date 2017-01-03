package hippo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

var ErrNoDeclarations = fmt.Errorf("No declarations in certificate")

// Subject associates a string identifier for some entity with its
// public key.
type Subject struct {
	ID        string
	PublicKey PublicKey
}

// Testament captures an assertion about a given subject.
type Testament struct {
	ID string // An optional identifier for this particular testament.

	Subject Subject // The subject of this assertion.
	Claims  Claims  // Arbitrary claims made about the subject, other than its identity.

	Expires string // Timepoint after which this Testament is to be considered invalid.
}

// Claims capture arbitrary key/value data.
type Claims map[string]interface{}

// Declaration binds an encoded Testament to a signature.
type Declaration struct {
	Claim     string    // Encoded Testament.
	Signer    string    // Optional identifier of the signer.
	Signature Signature // Cryptographic signature of the Claim.
}

// Chain is a list of Declarations
type Chain []*Declaration

// Certificate is simply a Chain.  It is encapsulated in the struct to
// ease some handling for serialization and other tasks, as well as
// possible future expansion to include other data.
type Certificate struct {
	Declarations Chain // All of the encoded and signed Testaments contained in this certificate.
}

// CertificateFromFile loads and parses a Certificate from the given
// file.  It does not verify the certificate.
func CertificateFromFile(fn string) (*Certificate, error) {

	var cert Certificate

	err := fromFile(fn, &cert)
	if err != nil {
		return nil, err
	}

	if len(cert.Declarations) <= 0 {
		return nil, ErrNoDeclarations
	}

	return &cert, nil

}

// CertificateFromBytes parses a Certificate from the given bytes.  It
// does not verify the certificate.
func CertificateFromBytes(buf []byte) (*Certificate, error) {

	var cert Certificate

	err := fromBytes(buf, &cert)
	if err != nil {
		return nil, err
	}

	if len(cert.Declarations) <= 0 {
		return nil, ErrNoDeclarations
	}

	return &cert, nil

}

// ToFile serializes the Certificate to the given file as JSON.
func (c *Certificate) ToFile(fn string) error {
	return toFile(c, fn)
}

// ToBytes serializes the Certificate to bytes as JSON.
func (c *Certificate) ToBytes() ([]byte, error) {
	return toBytes(c)
}

// NewTestament generates a Testament for the subject and claims.
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

// UnpackTestament parses a Testament from a JSON Base64-URL encoded
// string.
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

// Sign uses the given credentials to generate a Declaration,
// encapsulating the signer identity and a JSON Base64-URL encoding of
// the Testament.
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

// Base64 encodes the Testament as a JSON Base64-URL encoded string.
func (x *Testament) Base64() (string, error) {

	j, err := json.Marshal(x)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(j), nil

}
