package hippo

import (
	"testing"
)

func Test_Ed25519_01(t *testing.T) {
	test_basic(t, "ed25519")
}

func Test_Ed25519_02(t *testing.T) {

	public := PublicKey{
		Algorithm: "ed25519",
		Public: "40-exa2J4941Nn7eZS4R-uGqcXSMu3ye69s2xgAPyMg=",
	}

	signature := Signature("IVv3qM+gPCZdDccKoWLNNLN2Ycafg/0g9mB6G212XkPBNtlgCpHGr4LukNhooBIX9VZueyUnr4PqH8crnDwRBw==")

	test_signed(t, public, []byte("Four score and seven years ago"), signature)

}

func Test_Ed25519_03(t *testing.T) {
	test_json(t, "ed25519")
}
