package hippo

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

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

func test_signed(t *testing.T, public PublicKey, data []byte, signature Signature) {

	verifier, err := NewVerifier(public)
	require.Nil(t, err)
	require.NotNil(t, verifier)

	err = verifier.Verify(data, signature)
	require.Nil(t, err)

}

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

	/*
	 signaturejson,err := json.Marshal(signature)
	 require.Nil(t, err)
	 t.Log("Signature", string(signaturejson))
	*/

	public := PublicKey{}
	err = json.Unmarshal(publicjson, &public)
	require.Nil(t, err)

	/*
	 signature = &Signature{}
	 err = json.Unmarshal(signaturejson, signature)
	 require.Nil(t, err)
	*/

	receiver, err := NewVerifier(public)
	require.Nil(t, err)
	require.NotNil(t, receiver)

	err = receiver.Verify(data, signature)
	require.Nil(t, err)
	t.Log("Verified")

}
