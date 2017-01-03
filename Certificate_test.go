package hippo

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

// Test_Certificate_01: A CA generates a valid certificate for a user.
func Test_Certificate_01(t *testing.T) {

	user, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	testament := NewTestament("Joe", user.PublicKey(), nil)
	require.NotNil(t, testament)

	declaration, err := testament.Sign("CA", ca)
	require.Nil(t, err)
	require.NotNil(t, declaration)

	err = ca.Verify([]byte(declaration.Claim), declaration.Signature)
	require.Nil(t, err)

	certificate := &Certificate{Chain{declaration}}

	pool := NewVerifierPool()
	require.NotNil(t, pool)

	err = pool.Add("CA", ca)
	require.Nil(t, err)

	err = pool.Verify(certificate)
	require.Nil(t, err)

}

// Test_Certificate_02: A root CA generates a valid certificate for an
// intermediary CA which generates a valid certificate for a user.
func Test_Certificate_02(t *testing.T) {

	// Create some keys
	user, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	root, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	// Root makes a certificate for the CA
	ca_id := NewTestament("CA", ca.PublicKey(), Claims{"CertificateAuthority": true})
	require.NotNil(t, ca_id)

	ca_cert, err := ca_id.Sign("root", root)
	require.Nil(t, err)
	require.NotNil(t, ca_cert)

	// CA makes a certificate for the user
	user_id := NewTestament("Joe", user.PublicKey(), nil)
	require.NotNil(t, user_id)

	user_cert, err := user_id.Sign("CA", ca)
	require.Nil(t, err)
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	certificate := &Certificate{Chain{user_cert, ca_cert}}

	// Verify against a pool with the root
	pool := NewVerifierPool()
	require.NotNil(t, pool)

	err = pool.Add("root", root)
	require.Nil(t, err)

	err = pool.Verify(certificate)
	require.Nil(t, err)

}

// Test_Certificate_02a: This is the same as Test_Certificate_02
// except the certificate is marshaled to and unmarshaled from JSON.
func Test_Certificate_02a(t *testing.T) {

	// Create some keys
	user, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	root, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	// Root makes a certificate for the CA
	ca_id := NewTestament("CA", ca.PublicKey(), Claims{"CertificateAuthority": true})
	require.NotNil(t, ca_id)

	ca_cert, err := ca_id.Sign("root", root)
	require.Nil(t, err)
	require.NotNil(t, ca_cert)

	// CA makes a certificate for the user
	user_id := NewTestament("Joe", user.PublicKey(), nil)
	require.NotNil(t, user_id)

	user_cert, err := user_id.Sign("CA", ca)
	require.Nil(t, err)
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	out_certificate := &Certificate{Chain{user_cert, ca_cert}}

	bytes, err := json.Marshal(out_certificate)
	require.Nil(t, err)

	var in_certificate Certificate
	err = json.Unmarshal(bytes, &in_certificate)
	require.Nil(t, err)

	// Verify against a pool with the root
	pool := NewVerifierPool()
	require.NotNil(t, pool)

	err = pool.Add("root", root)
	require.Nil(t, err)

	err = pool.Verify(&in_certificate)
	require.Nil(t, err)

}

// Test_Certificate_03: A root CA generates a valid certificate for a
// bad actor that tries to use its certificate to generate a valid
// certificate for a user, but it is rejected because the root CA did
// not certify it as a certificate authority.
func Test_Certificate_03(t *testing.T) {

	// Create some keys
	user, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	root, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	// Root makes a certificate for the bogus CA
	ca_id := NewTestament("CA", ca.PublicKey(), nil)
	require.NotNil(t, ca_id)

	ca_cert, err := ca_id.Sign("root", root)
	require.Nil(t, err)
	require.NotNil(t, ca_cert)

	// Bogus CA makes a certificate for the user
	user_id := NewTestament("Joe", user.PublicKey(), nil)
	require.NotNil(t, user_id)

	user_cert, err := user_id.Sign("CA", ca)
	require.Nil(t, err)
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	certificate := &Certificate{Chain{user_cert, ca_cert}}

	// Verify against a pool with the root
	pool := NewVerifierPool()
	require.NotNil(t, pool)

	err = pool.Add("root", root)
	require.Nil(t, err)

	err = pool.Verify(certificate)
	require.NotNil(t, err)
	require.Equal(t, NotCertificateAuthority, err)

}

// Test_Certificate_03a: This is the same as Test_Certificate_03
// except that the certificate is marshaled to and unmarshaled from
// JSON before being rejected.
func Test_Certificate_03a(t *testing.T) {

	// Create some keys
	user, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	root, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	// Root makes a certificate for the CA
	ca_id := NewTestament("CA", ca.PublicKey(), nil)
	require.NotNil(t, ca_id)

	ca_cert, err := ca_id.Sign("root", root)
	require.Nil(t, err)
	require.NotNil(t, ca_cert)

	// Bogus CA makes a certificate for the user
	user_id := NewTestament("Joe", user.PublicKey(), nil)
	require.NotNil(t, user_id)

	user_cert, err := user_id.Sign("CA", ca)
	require.Nil(t, err)
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	out_certificate := &Certificate{Chain{user_cert, ca_cert}}

	bytes, err := json.Marshal(out_certificate)
	require.Nil(t, err)

	var in_certificate Certificate
	err = json.Unmarshal(bytes, &in_certificate)
	require.Nil(t, err)

	// Verify against a pool with the root
	pool := NewVerifierPool()
	require.NotNil(t, pool)

	err = pool.Add("root", root)
	require.Nil(t, err)

	err = pool.Verify(&in_certificate)
	require.NotNil(t, err)
	require.Equal(t, NotCertificateAuthority, err)

}

// Test_Certificate_04: A root CA authorizes a valid CA, but a user
// appends that valid certificate segment to an invalid certificate
// for itself and is rejected.
func Test_Certificate_04(t *testing.T) {

	// Create some keys
	user, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	root, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	bogusca, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, bogusca)

	// Root makes a certificate for the CA
	ca_id := NewTestament("CA", ca.PublicKey(), Claims{"CertificateAuthority": true})
	require.NotNil(t, ca_id)

	ca_cert, err := ca_id.Sign("root", root)
	require.Nil(t, err)
	require.NotNil(t, ca_cert)

	// Bogus CA makes a certificate for the user
	user_id := NewTestament("Joe", user.PublicKey(), nil)
	require.NotNil(t, user_id)

	user_cert, err := user_id.Sign("CA", bogusca)
	require.Nil(t, err)
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	certificate := &Certificate{Chain{user_cert, ca_cert}}

	// Verify against a pool with the root
	pool := NewVerifierPool()
	require.NotNil(t, pool)

	err = pool.Add("root", root)
	require.Nil(t, err)

	err = pool.Verify(certificate)
	require.NotNil(t, err)
	require.Equal(t, UnverifiedSignature, err)

}

// Test_Certificate_04a: This is the same as Test_Certificate_04
// except the certificate is marshaled to and then unmarshaled from
// JSON before being tested and rejecting the user.
func Test_Certificate_04a(t *testing.T) {

	// Create some keys
	user, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	root, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	bogusca, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, bogusca)

	// Root makes a certificate for the CA
	ca_id := NewTestament("CA", ca.PublicKey(), Claims{"CertificateAuthority": true})
	require.NotNil(t, ca_id)

	ca_cert, err := ca_id.Sign("root", root)
	require.Nil(t, err)
	require.NotNil(t, ca_cert)

	// Bogus CA makes a certificate for the user
	user_id := NewTestament("Joe", user.PublicKey(), nil)
	require.NotNil(t, user_id)

	user_cert, err := user_id.Sign("CA", bogusca)
	require.Nil(t, err)
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	out_certificate := &Certificate{Chain{user_cert, ca_cert}}

	bytes, err := json.Marshal(out_certificate)
	require.Nil(t, err)

	var in_certificate Certificate
	err = json.Unmarshal(bytes, &in_certificate)
	require.Nil(t, err)

	// Verify against a pool with the root
	pool := NewVerifierPool()
	require.NotNil(t, pool)

	err = pool.Add("root", root)
	require.Nil(t, err)

	err = pool.Verify(&in_certificate)
	require.NotNil(t, err)
	require.Equal(t, UnverifiedSignature, err)

}

// Test_Certificate_05: A root CA generates a valid certificate for an
// intermediary CA which generates a valid certificate for a secondary
// CA which in turn generates a valid certificate for a user.
func Test_Certificate_05(t *testing.T) {

	// Create some keys
	user, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca1, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca1)

	ca2, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca2)

	root, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	// Root makes a certificate for CA1
	ca1_id := NewTestament("ca1", ca1.PublicKey(), Claims{"CertificateAuthority": true})
	require.NotNil(t, ca1_id)

	ca1_cert, err := ca1_id.Sign("root", root)
	require.Nil(t, err)
	require.NotNil(t, ca1_cert)

	// CA1 makes a certificate for CA2
	ca2_id := NewTestament("ca2", ca2.PublicKey(), Claims{"CertificateAuthority": true})
	require.NotNil(t, ca2_id)

	ca2_cert, err := ca2_id.Sign("ca1", ca1)
	require.Nil(t, err)
	require.NotNil(t, ca2_cert)

	// CA2 makes a certificate for the user
	user_id := NewTestament("Joe", user.PublicKey(), nil)
	require.NotNil(t, user_id)

	user_cert, err := user_id.Sign("ca2", ca2)
	require.Nil(t, err)
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	out_certificate := &Certificate{Chain{user_cert, ca2_cert, ca1_cert}}

	// Marshal to JSON to share the certificate somehow
	bytes, err := out_certificate.ToBytes()
	require.Nil(t, err)

	// Unmarshal the shared certificate
	var in_certificate Certificate
	err = json.Unmarshal(bytes, &in_certificate)
	require.Nil(t, err)

	// Verify against a pool comprised of the root
	pool := NewVerifierPool()
	require.NotNil(t, pool)

	err = pool.Add("root", root)
	require.Nil(t, err)

	err = pool.Verify(&in_certificate)
	require.Nil(t, err)

}

// Test_Certificate_06: An invalid CA generates a certificate for an
// intermediary CA which in turn generates a certificate for a user,
// which is rejected.
func Test_Certificate_06(t *testing.T) {

	// Create some keys
	user, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca1, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca1)

	ca2, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca2)

	root, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	bogus, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	// CA1 makes a bogus certificate for itself
	ca1_id := NewTestament("ca1", ca1.PublicKey(), Claims{"CertificateAuthority": true})
	require.NotNil(t, ca1_id)

	ca1_cert, err := ca1_id.Sign("root", bogus)
	require.Nil(t, err)
	require.NotNil(t, ca1_cert)

	// CA1 makes a certificate for CA2
	ca2_id := NewTestament("ca2", ca2.PublicKey(), Claims{"CertificateAuthority": true})
	require.NotNil(t, ca2_id)

	ca2_cert, err := ca2_id.Sign("ca1", ca1)
	require.Nil(t, err)
	require.NotNil(t, ca2_cert)

	// CA2 makes a certificate for the user
	user_id := NewTestament("Joe", user.PublicKey(), nil)
	require.NotNil(t, user_id)

	user_cert, err := user_id.Sign("ca2", ca2)
	require.Nil(t, err)
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	out_certificate := &Certificate{Chain{user_cert, ca2_cert, ca1_cert}}
	bytes, err := out_certificate.ToBytes()
	require.Nil(t, err)

	var in_certificate Certificate
	err = json.Unmarshal(bytes, &in_certificate)
	require.Nil(t, err)

	// Verify against a pool with the root
	pool := NewVerifierPool()
	require.NotNil(t, pool)

	err = pool.Add("root", root)
	require.Nil(t, err)

	err = pool.Verify(&in_certificate)
	require.NotNil(t, err)
	require.Equal(t, UnrecognizedCertificate, err)

}
