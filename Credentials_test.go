package hippo

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

// test_basic is a test utility function to generate credentials using
// the given algorithm and then sign and verify some data using them.
func test_basic(t *testing.T, algorithm string) {

	data := []byte("Four score and seven years ago")

	sender, err := Generate(algorithm)
	require.Nil(t, err)
	require.NotNil(t, sender)

	signature, err := sender.Sign(data)
	require.Nil(t, err)
	require.NotEmpty(t, signature)

	public := sender.PublicKey()
	receiver, err := NewVerifier(public)
	require.Nil(t, err)
	require.NotNil(t, receiver)

	err = receiver.Verify(data, signature)
	require.Nil(t, err)
	t.Log("Public Key", fmt.Sprintf("%s:%v", public.Algorithm, public.Public))
	t.Log("Signature", signature)
	t.Log("Verified")

}

// test_bogus is a test utility function to generate two sets of
// credentials using the given algorithm, then sign the data with one
// set but verify and reject with the other set.
func test_bogus(t *testing.T, algorithm string) {

	data := []byte("It's too bad she wont live, but then again who does?")

	sender, err := Generate(algorithm)
	require.Nil(t, err)
	require.NotNil(t, sender)

	attacker, err := Generate(algorithm)
	require.Nil(t, err)
	require.NotNil(t, sender)

	signature, err := attacker.Sign(data)
	require.Nil(t, err)
	require.NotEmpty(t, signature)

	receiver, err := NewVerifier(sender.PublicKey())
	require.Nil(t, err)
	require.NotNil(t, receiver)

	err = receiver.Verify(data, signature)
	require.NotNil(t, err)
	require.Equal(t, UnverifiedSignature, err)

}

// test_signed is a test utility function to take signed data and
// verify it against the given public key.
func test_signed(t *testing.T, public PublicKey, data []byte, signature Signature) {

	verifier, err := NewVerifier(public)
	require.Nil(t, err)
	require.NotNil(t, verifier)

	err = verifier.Verify(data, signature)
	require.Nil(t, err)

}

// test_json is a test utility function that generates credentials
// using the given algorithm, signs some data using them, marshals the
// public key to JSON, and then unmarshals the JSON and verifies the
// data against the extracted public key.
func test_json(t *testing.T, algorithm string) {

	data := []byte("Four score and seven years ago")

	sender, err := Generate(algorithm)
	require.Nil(t, err)
	require.NotNil(t, sender)

	publicjson, err := json.Marshal(sender.PublicKey())
	require.Nil(t, err)
	t.Log("Public Key", string(publicjson))

	signature, err := sender.Sign(data)
	require.Nil(t, err)

	public := PublicKey{}
	err = json.Unmarshal(publicjson, &public)
	require.Nil(t, err)

	receiver, err := NewVerifier(public)
	require.Nil(t, err)
	require.NotNil(t, receiver)

	err = receiver.Verify(data, signature)
	require.Nil(t, err)
	t.Log("Verified")

}
