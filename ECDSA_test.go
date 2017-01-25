package hippo

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Test_ECDSA_01: Generate credentials then sign & verify data.
func Test_ECDSA_01(t *testing.T) {
	test_credentials_basic(t, "ecdsa-p256")
}

// Test_ECDSA_02: Generate credentials for sender and attacker, sign
// data using the latter, verify that the sender did not sign it.
func Test_ECDSA_02(t *testing.T) {
	test_credentials_bogus(t, "ecdsa-p256")
}

// Test_ECDSA_03: Verify a given signature against a given public key.
func Test_ECDSA_03(t *testing.T) {

	/*
		    // Signature was generated from Javascript using this key data
				private := PrivateKey{
					Algorithm: "ecdsa-p256",
				Private: map[string]interface{} {
						"X": "vHGHboq781mKvPK9MSPjAiF8cWgfI0lp0npkQGjBCH4",
						"Y": "85H9JKx9LfzDKm7ylLCXI5gyuy1SMeenZnG3Gk72G1w",
						"D": "By7yMbeb8tAGDdcIStukBFDeOoUSiYUuMxTdZelMoU4",
					},
				}
	*/

	public := PublicKey{
		Algorithm: "ecdsa-p256",
		Public: map[string]interface{}{
			"X": "vHGHboq781mKvPK9MSPjAiF8cWgfI0lp0npkQGjBCH4",
			"Y": "85H9JKx9LfzDKm7ylLCXI5gyuy1SMeenZnG3Gk72G1w",
		},
	}

	data := []byte{77, 117, 115, 104, 105, 32, 109, 117, 115, 104, 105}
	signature := Signature("Z8x1sWscIaeL1XAtmzXbKH+bn57mscRNO5G9C336Dvk67b7mv17H3mWxSA++hIHVzTpgG3ruXadpI0jSd6W/vQ==")

	test_credentials_signed(t, public, data, signature)

}

// Test_ECDSA_04: Generate credentials, sign some data, then marshal
// and unmarshal the public key to/from JSON before verifying.
func Test_ECDSA_04(t *testing.T) {
	test_credentials_json(t, "ecdsa-p256")
}

// Test_ECDSA_05: Sign some data using a given private key, then
// verify it using a given public key.  This test ensures
// compatibility with output from Javascript's WebCrypto API, which is
// where the key data comes from.
func Test_ECDSA_05(t *testing.T) {

	data := []byte("If you're the last man standing, you're not fighting hard enough!")

	private := PrivateKey{
		Algorithm: "ecdsa-p256",
		Private: map[string]interface{}{
			"X": "tWkFZSoWKmWbKYAeUu_0VYparnc1KsC_Fi7Hufx6aGU",
			"Y": "n_UdGXe2qTC81ttqx4HckQ4oVMA41EcyGlMqrl_GO_g",
			"D": "s_T7r4eLmb6RxF7jWOaHZUBy3DZ0TSOCrGoipwmU3cI",
		},
	}

	public := PublicKey{
		Algorithm: "ecdsa-p256",
		Public: map[string]interface{}{
			"X": "tWkFZSoWKmWbKYAeUu_0VYparnc1KsC_Fi7Hufx6aGU",
			"Y": "n_UdGXe2qTC81ttqx4HckQ4oVMA41EcyGlMqrl_GO_g",
		},
	}

	signer, err := NewSigner(private)
	require.Nil(t, err)
	require.NotNil(t, signer)

	verifier, err := NewVerifier(public)
	require.Nil(t, err)
	require.NotNil(t, verifier)

	signature, err := signer.Sign(data)
	require.Nil(t, err)
	require.NotEmpty(t, signature)

	err = verifier.Verify(data, signature)
	require.Nil(t, err)

}
