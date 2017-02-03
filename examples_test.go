package hippo

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Example_Sign is a minimal demonstration of generating a key,
// signing some data, sharing the key bytes, and verifying the data.
func Example_Sign() {

	// GenerateCredentials a key
	sender, err := GenerateCredentials("ed25519")
	if err != nil {
		panic(err)
	}

	// Sign some data with that key
	data := []byte("Four score and seven years ago")
	signature, err := sender.Sign(data)
	if err != nil {
		panic(err)
	}

	// Marshal the key to JSON to share it somehow
	sharedkey, err := json.Marshal(sender.PublicKey())
	if err != nil {
		panic(err)
	}

	// Receive a shared key as JSON and unmarshal
	publickey := PublicKey{}
	err = json.Unmarshal(sharedkey, &publickey)
	if err != nil {
		panic(err)
	}

	// Turn the key into an actionable verifier (before this it's just
	// data, the Verifier is an object with specific crypto methods)
	verifier, err := NewVerifier(publickey)
	if err != nil {
		panic(err)
	}

	// Verify that this key did sign the data
	err = verifier.Verify(data, signature)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Verified")

	// Output: Verified
}

// Example_CertificateChain shows a root CA generating a valid
// certificate for an intermediary CA, which generates a valid
// certificate for a secondary CA, which in turn generates a valid
// certificate for a user that is verified against a pool including
// just the root CA.
func Example_CertificateChain() {

	// Create some keys
	user, err := GenerateCredentials(AlgorithmEd25519)
	if err != nil {
		panic(err)
	}

	ca1, err := GenerateCredentials(AlgorithmECDSA_P256)
	if err != nil {
		panic(err)
	}

	ca2, err := GenerateCredentials(AlgorithmECDSA_P256)
	if err != nil {
		panic(err)
	}

	root, err := GenerateCredentials(AlgorithmEd25519)
	if err != nil {
		panic(err)
	}

	// Root makes a certificate for CA1
	ca1_id := NewTestament("ca1", ca1.PublicKey(), Claims{"CertificateAuthority": true})

	ca1_cert, err := ca1_id.Sign("root", root)
	if err != nil {
		panic(err)
	}

	// CA1 makes a certificate for CA2
	ca2_id := NewTestament("ca2", ca2.PublicKey(), Claims{"CertificateAuthority": true})

	ca2_cert, err := ca2_id.Sign("ca1", ca1)
	if err != nil {
		panic(err)
	}

	// CA2 makes a certificate for the user
	user_id := NewTestament("Joe", user.PublicKey(), nil)

	user_cert, err := user_id.Sign("ca2", ca2)
	if err != nil {
		panic(err)
	}

	// Put them together to make a certificate
	out_certificate := &Certificate{Chain{user_cert, ca2_cert, ca1_cert}}

	// Marshal to JSON to share the certificate somehow
	bytes, err := out_certificate.ToBytes()
	if err != nil {
		panic(err)
	}

	// Unmarshal the shared certificate
	var in_certificate Certificate
	err = json.Unmarshal(bytes, &in_certificate)
	if err != nil {
		panic(err)
	}

	// Create a pool comprised of the root
	pool := NewVerifierPool()

	err = pool.Add("root", root)
	if err != nil {
		panic(err)
	}

	// Verify the certificate against the pool
	err = pool.Verify(&in_certificate)
	if err != nil {
		panic(err)
	}

	fmt.Println("Verified")

	// Output: Verified
}

// Example_Encrypt is a minimal demonstration of generating a key,
// marshaling it to JSON, encrypting data with the unmarshalled key,
// and then decrypting the data from the original key.
func Example_Encrypt() {

	data := []byte("Four score and seven years ago")

	// Create a keypair
	keys, err := GeneratePKCipher("rsa-oaep-2048")
	if err != nil { panic(err) }

	// Marshal the public key out to JSON
	publicjson, err := json.Marshal(keys.PublicKey())
	if err != nil { panic(err) }

	// Read the public key back in
	public := PublicKey{}
	err = json.Unmarshal(publicjson, &public)
	if err != nil { panic(err) }

	encrypter, err := NewEncrypter(public)
	if err != nil { panic(err) }

	// Encrypt the data from the unmarshaled public key
	ciphertext, err := encrypter.Encrypt(data)
	if err != nil { panic(err) }

	// Decrypt the data with the original private key
	cleartext, err := keys.Decrypt(ciphertext)
	if err != nil { panic(err) }

	if bytes.Compare(cleartext, data) != 0 {
		panic("Data mismatch!")
	}

	fmt.Println("Received")

	// Output: Received
}
