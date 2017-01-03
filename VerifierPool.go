package hippo

import (
	"fmt"
	//	"encoding/base64"
	//	"encoding/json"
)

var ErrPreviousVerifier = fmt.Errorf("Verifier exists")
var ErrNoVerifier = fmt.Errorf("Invalid verifier")
var ErrInvalidCertificate = fmt.Errorf("Invalid certificate")
var ErrUnrecognizedCertificate = fmt.Errorf("Unrecognized certificate")
var ErrBrokenCertificateChain = fmt.Errorf("Broken certificate chain")
var ErrNotCertificateAuthority = fmt.Errorf("Chained declaration does not confirm certificate authority")

// VerifierPool is a collection of verifiers.  Typically these are
// used to group a set of keys for trusted entities that may be used
// to verify incoming data, etc..
type VerifierPool struct {
	verifiers map[string]Verifier
}

// NewVerifierPool creates an empty VerifierPool.
func NewVerifierPool() *VerifierPool {

	x := new(VerifierPool)
	x.verifiers = make(map[string]Verifier)

	return x

}

// Add adds to given verifier to the pool under the given identifier.
func (x VerifierPool) Add(id string, v Verifier) error {

	_, ok := x.verifiers[id]
	if ok {
		return ErrPreviousVerifier
	}

	x.verifiers[id] = v

	return nil

}

// VerifySpecific looks up the given identifier in the pool and
// confirms that the signature was created from the data by the
// private key associated with that verifier's public key.
func (x VerifierPool) VerifySpecific(id string, data []byte, signature Signature) error {

	verifier, ok := x.verifiers[id]
	if !ok {
		return ErrNoVerifier
	}

	return verifier.Verify(data, signature)

}

// VerifyAny checks if any entry in the pool can verify that the
// signature was created from the data by the private key associated
// with that verifier's public key.
func (x VerifierPool) VerifyAny(data []byte, signature Signature) error {

	var err error
	for _, verifier := range x.verifiers {
		err = verifier.Verify(data, signature)
		if err == nil {
			return nil
		}
	}

	return ErrUnverifiedSignature

}

// VerifyDeclaration confirms that the declaration can be verified by
// the entry in the pool under the included signer identity if it is
// not blank, or by entry in the pool if it is.
func (x VerifierPool) VerifyDeclaration(declaration *Declaration) error {

	if declaration.Signer == "" {
		return x.VerifyAny([]byte(declaration.Claim), declaration.Signature)
	}

	return x.VerifySpecific(declaration.Signer, []byte(declaration.Claim), declaration.Signature)

}

// Verify confirms that each Declaration in the Certificate Chain was
// signed by the entitiy associated with the subsequent entry, that
// each intermediate signer was indicated by its successor to be a
// certificate authority, and that the chain at some point leads to an
// entry in the verifier pool.
func (x VerifierPool) Verify(cert *Certificate) error {

	// If there's no certificate, fail
	if len(cert.Declarations) <= 0 {
		return ErrInvalidCertificate
	}

	// If the first signer is in the pool, approve
	err := x.VerifyDeclaration(cert.Declarations[0])
	if err == nil {
		return nil
	}

	prev := cert.Declarations[0]

	for index := 1; index < len(cert.Declarations); index++ {

		current := cert.Declarations[index]
		currtestament, err := UnpackTestament(current.Claim)

		// If a chained declaration is not for a certificate authority, fail
		val, ok := currtestament.Claims["CertificateAuthority"]
		if !ok {
			return ErrNotCertificateAuthority
		}

		switch t := val.(type) {
		case bool:
			if !t {
				return ErrNotCertificateAuthority
			}
		default:
			return ErrNotCertificateAuthority
		}

		// If the public key does not link to the preceding declaration, fail
		if currtestament.Subject.ID != prev.Signer {
			return ErrBrokenCertificateChain
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
	return ErrUnrecognizedCertificate

}
