package hippo

import (
	"github.com/stretchr/testify/require"
	"testing"
)

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

	err = pool.VerifyAny(data, signature)
	require.Nil(t, err)

	err = pool.VerifySpecific("foo", data, signature)
	require.Nil(t, err)

}

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

	err = pool.VerifySpecific("foo", data, signature)
	require.NotNil(t, err)

}
