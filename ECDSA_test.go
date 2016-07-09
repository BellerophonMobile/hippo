package hippo

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_ECDSA_01(t *testing.T) {
	test_basic(t, "ecdsa-p256")
}

func Test_ECDSA_02(t *testing.T) {
	test_json(t, "ecdsa-p256")
}

func Test_ECDSA_03(t *testing.T) {

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

	t.Log("Verified")

}

func Test_ECDSA_04(t *testing.T) {

	data := []byte{77, 117, 115, 104, 105, 32, 109, 117, 115, 104, 105}

	/*
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

	signature := Signature("Z8x1sWscIaeL1XAtmzXbKH+bn57mscRNO5G9C336Dvk67b7mv17H3mWxSA++hIHVzTpgG3ruXadpI0jSd6W/vQ==")

	verifier, err := NewVerifier(public)
	require.Nil(t, err)
	require.NotNil(t, verifier)

	err = verifier.Verify(data, signature)
	require.Nil(t, err)

	t.Log("Verified")

}
