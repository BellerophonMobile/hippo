package hippo

import (
	"testing"
)

// Test_Ed25519_01: Generate credentials then sign & verify data.
func Test_Ed25519_01(t *testing.T) {
	test_basic(t, "ed25519")
}

// Test_Ed25519_02: Generate credentials for sender and attacker, sign
// data using the latter, verify that the sender did not sign it.
func Test_Ed25519_02(t *testing.T) {
	test_bogus(t, "ed25519")
}

// Test_Ed25519_03: Verify a given signature against a given public key.
func Test_Ed25519_03(t *testing.T) {

	public := PublicKey{
		Algorithm: "ed25519",
		Public:    "40-exa2J4941Nn7eZS4R-uGqcXSMu3ye69s2xgAPyMg=",
	}

	data := []byte("Four score and seven years ago")
	signature := Signature("IVv3qM+gPCZdDccKoWLNNLN2Ycafg/0g9mB6G212XkPBNtlgCpHGr4LukNhooBIX9VZueyUnr4PqH8crnDwRBw==")

	test_signed(t, public, data, signature)

}

// Test_ECDSA_04: Generate credentials, sign some data, then marshal
// and unmarshal the public key to/from JSON before verifying.
func Test_Ed25519_04(t *testing.T) {
	test_json(t, "ed25519")
}
