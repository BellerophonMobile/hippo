package hippo

import (
	"testing"
	"github.com/stretchr/testify/require"
	"encoding/json"
)

func Test_Certificate_01(t *testing.T) {

	user,err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca,err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)


	testament := NewTestament("Joe", user.PublicKey())
	require.NotNil(t, testament)

	declaration,err := testament.Sign("CA", ca)
	require.Nil(t, err)	
	require.NotNil(t, declaration)

	err = ca.Verify([]byte(declaration.Claim), declaration.Signature)
	require.Nil(t, err)


	certificate := &Certificate{ Chain{ declaration } }

	pool := NewVerifierPool()
	require.NotNil(t, pool)
	
	err = pool.Add("CA", ca)
	require.Nil(t, err)
	
	err = pool.Verify(certificate)
	require.Nil(t, err)

}

func Test_Certificate_02(t *testing.T) {

	// Create some keys
	user,err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca,err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	root,err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	
	// Root makes a certificate for the CA
	ca_id := NewTestament("CA", ca.PublicKey())
	require.NotNil(t, ca_id)
	
	ca_cert,err := ca_id.Sign("root", root)
	require.Nil(t, err)	
	require.NotNil(t, ca_cert)

	// CA makes a certificate for the user	
	user_id := NewTestament("Joe", user.PublicKey())
	require.NotNil(t, user_id)

	user_cert,err := user_id.Sign("CA", ca)
	require.Nil(t, err)	
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	certificate := &Certificate{ Chain{ user_cert, ca_cert } }

	// Verify against a pool with the root
	pool := NewVerifierPool()
	require.NotNil(t, pool)
	
	err = pool.Add("root", root)
	require.Nil(t, err)
	
	err = pool.Verify(certificate)
	require.Nil(t, err)

}

func Test_Certificate_03(t *testing.T) {

	// Create some keys
	user,err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca,err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	root,err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	bogusca,err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, bogusca)

	
	// Root makes a certificate for the CA
	ca_id := NewTestament("CA", ca.PublicKey())
	require.NotNil(t, ca_id)
	
	ca_cert,err := ca_id.Sign("root", root)
	require.Nil(t, err)	
	require.NotNil(t, ca_cert)

	// Bocus CA makes a certificate for the user	
	user_id := NewTestament("Joe", user.PublicKey())
	require.NotNil(t, user_id)

	user_cert,err := user_id.Sign("CA", bogusca)
	require.Nil(t, err)	
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	certificate := &Certificate{ Chain{ user_cert, ca_cert } }


	// Verify against a pool with the root
	pool := NewVerifierPool()
	require.NotNil(t, pool)
	
	err = pool.Add("root", root)
	require.Nil(t, err)
	
	err = pool.Verify(certificate)
	require.NotNil(t, err)
	t.Log(err)

}

func Test_Certificate_04(t *testing.T) {

	// Create some keys
	user,err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca,err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	root,err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)

	bogusca,err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, bogusca)

	
	// Root makes a certificate for the CA
	ca_id := NewTestament("CA", ca.PublicKey())
	require.NotNil(t, ca_id)
	
	ca_cert,err := ca_id.Sign("root", root)
	require.Nil(t, err)	
	require.NotNil(t, ca_cert)

	// Bocus CA makes a certificate for the user	
	user_id := NewTestament("Joe", user.PublicKey())
	require.NotNil(t, user_id)

	user_cert,err := user_id.Sign("CA", bogusca)
	require.Nil(t, err)	
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	out_certificate := &Certificate{ Chain{ user_cert, ca_cert } }

	bytes,err := json.Marshal(out_certificate)
	require.Nil(t, err)
	t.Log(string(bytes))
	
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
	t.Log(err)

}

func Test_Certificate_05(t *testing.T) {

	// Create some keys
	user,err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, user)

	ca,err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	require.NotNil(t, ca)

	root,err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	require.NotNil(t, root)
	
	// Root makes a certificate for the CA
	ca_id := NewTestament("CA", ca.PublicKey())
	require.NotNil(t, ca_id)
	
	ca_cert,err := ca_id.Sign("root", root)
	require.Nil(t, err)	
	require.NotNil(t, ca_cert)

	// Bocus CA makes a certificate for the user	
	user_id := NewTestament("Joe", user.PublicKey())
	require.NotNil(t, user_id)

	user_cert,err := user_id.Sign("CA", ca)
	require.Nil(t, err)	
	require.NotNil(t, user_cert)

	// Put them together to make a certificate
	out_certificate := &Certificate{ Chain{ user_cert, ca_cert } }

	bytes,err := json.Marshal(out_certificate)
	require.Nil(t, err)
	t.Log(string(bytes))
	
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
	t.Log(err)

}
