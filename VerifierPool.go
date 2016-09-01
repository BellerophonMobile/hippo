package hippo

import (
	"fmt"
	//	"encoding/base64"
	//	"encoding/json"
)

var PreviousVerifier = fmt.Errorf("Verifier exists")
var NoVerifier = fmt.Errorf("Invalid verifier")

var InvalidCertificate = fmt.Errorf("Invalid certificate")

var UnverifiedCertificate = fmt.Errorf("Unrecognized certificate")

var BrokenCertificateChain = fmt.Errorf("Broken certificate chain")

var NotCertificateAuthority = fmt.Errorf("Chained declaration does not confirm certificate authority")

type VerifierPool struct {
	verifiers map[string]Verifier
}

func NewVerifierPool() *VerifierPool {

	x := new(VerifierPool)
	x.verifiers = make(map[string]Verifier)

	return x

}

func (x VerifierPool) Add(id string, v Verifier) error {

	_, ok := x.verifiers[id]
	if ok {
		return PreviousVerifier
	}

	x.verifiers[id] = v

	return nil

}

func (x VerifierPool) VerifySpecific(id string, data []byte, signature Signature) error {

	verifier, ok := x.verifiers[id]
	if !ok {
		return NoVerifier
	}

	return verifier.Verify(data, signature)

}

func (x VerifierPool) VerifyAny(data []byte, signature Signature) error {

	var err error
	for _, verifier := range x.verifiers {
		err = verifier.Verify(data, signature)
		if err == nil {
			return nil
		}
	}

	return UnverifiedSignature

}

func (x VerifierPool) VerifyDeclaration(declaration *Declaration) error {

	if declaration.Signer == "" {
		return x.VerifyAny([]byte(declaration.Claim), declaration.Signature)
	}

	return x.VerifySpecific(declaration.Signer, []byte(declaration.Claim), declaration.Signature)

}

func (x VerifierPool) Verify(cert *Certificate) error {

	// If there's no certificate, fail
	if len(cert.Declarations) <= 0 {
		return InvalidCertificate
	}

	// If the first signer is in the pool, approve
	err := x.VerifyDeclaration(cert.Declarations[0])
	if err == nil {
		return nil
	}

	index := 1
	prev := cert.Declarations[0]

	for index < len(cert.Declarations) {

		current := cert.Declarations[index]
		currtestament, err := UnpackTestament(current.Claim)

		// If a chained declaration is not for a certificate authority, fail
		val, ok := currtestament.Claims["CertificateAuthority"]
		if !ok {
			return NotCertificateAuthority
		}

		switch t := val.(type) {
		case bool:
			if !t {
				return NotCertificateAuthority
			}
		default:
			return NotCertificateAuthority
		}

		// If the public key does not link to the preceding declaration, fail
		if currtestament.Subject.ID != prev.Signer {
			return BrokenCertificateChain
		}

		v, err := NewVerifier(currtestament.Subject.PublicKey)
		if err != nil {
			return err
		}

		err = v.Verify([]byte(prev.Claim), prev.Signature)
		if err != nil {
			return err
		}

		// If that signer is in the pool, approve
		err = x.VerifyDeclaration(current)
		if err == nil {
			return nil
		}

		prev = current
	}

	// None of the signers were in the pool, fail
	return UnverifiedCertificate

}
