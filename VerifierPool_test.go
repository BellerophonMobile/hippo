package hippo

import (
	"github.com/stretchr/testify/require"
	"testing"
)

// Test_Pool_01: Generate credentials, add them to a pool, sign some
// data, and then confirm that some entity in the pool and then that
// id specifically can verify the signature.
func Test_Pool_01(t *testing.T) {

	pool := NewVerifierPool()

	foo, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	err = pool.Add("foo", foo)
	require.Nil(t, err)

	data := []byte("When in the course of human events")

	signature, err := foo.Sign(data)
	require.Nil(t, err)
	require.NotEmpty(t, signature)

	// Test that the data has been signed by some known source.
	err = pool.VerifyAny(data, signature)
	require.Nil(t, err)

	err = pool.VerifySpecific("foo", data, signature)
	require.Nil(t, err)

}

// Test_Pool_02: Generate two sets of credentials, add them to a pool,
// sign some data using the first, and then confirm that some entity
// in the pool and then that id specifically can verify the signature.
func Test_Pool_02(t *testing.T) {

	pool := NewVerifierPool()

	foo, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	err = pool.Add("foo", foo)
	require.Nil(t, err)

	bar, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	err = pool.Add("bar", bar)
	require.Nil(t, err)

	data := []byte("When in the course of human events")

	signature, err := foo.Sign(data)
	require.Nil(t, err)
	require.NotEmpty(t, signature)

	err = pool.VerifyAny(data, signature)
	require.Nil(t, err)

	err = pool.VerifySpecific("foo", data, signature)
	require.Nil(t, err)

}

// Test_Pool_03: Generate three sets of credentials, add two to a
// pool, sign some data using the third, and confirm that no entity in
// the pool can verify, a verifier ID not present in the pool
// generates an error, and a given verifier present in the pool cannot
// verify either.
func Test_Pool_03(t *testing.T) {

	pool := NewVerifierPool()

	foo, err := Generate(AlgorithmEd25519)
	require.Nil(t, err)
	err = pool.Add("foo", foo)
	require.Nil(t, err)

	bar, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)
	err = pool.Add("bar", bar)
	require.Nil(t, err)

	crabapple, err := Generate(AlgorithmECDSA_P256)
	require.Nil(t, err)

	data := []byte("When in the course of human events")

	signature, err := crabapple.Sign(data)
	require.Nil(t, err)
	require.NotEmpty(t, signature)

	err = pool.VerifyAny(data, signature)
	require.NotNil(t, err)

	err = pool.VerifySpecific("crabapple", data, signature)
	require.NotNil(t, err)
	require.Equal(t, ErrNoVerifier, err)

	err = pool.VerifySpecific("foo", data, signature)
	require.NotNil(t, err)
	require.Equal(t, ErrUnverifiedSignature, err)

}
