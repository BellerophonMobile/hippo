package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/BellerophonMobile/hippo"
	"github.com/BellerophonMobile/logberry"
)

type claims map[string]interface{}

func (c claims) String() string {
	return "asdf"
}

func (c claims) Set(flag string) error {
	v := strings.SplitAfterN(flag, ",", 2)
	if len(v) != 2 {
		return fmt.Errorf("Claim format is \"key,value\"")
	}

	key := v[0][:len(v[0])-1]

	dec := json.NewDecoder(strings.NewReader(v[1]))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("Invalid claim value format")
	}

	switch tok := tok.(type) {
	case bool, string:
		c[key] = tok

	case json.Number:
		// First try to decode as int
		c[key], err = tok.Int64()
		if err == nil {
			break
		}
		// Next try float
		c[key], err = tok.Float64()
		if err == nil {
			break
		}
		// Finally, just store the string value
		c[key] = tok.String()

	default:
		return fmt.Errorf("Invalid claim value type")
	}

	return nil
}

func main() {
	certId := flag.String("certid", "", "Certificate ID.")
	subjectId := flag.String("subjectid", "", "Subject ID.")
	publicKeyFile := flag.String("subjectkey", "", "Subject public key.")
	signingKeyFile := flag.String("signingkey", "", "Signing private key.")
	outFile := flag.String("out", "", "Output certificate.")

	claims := make(claims)

	flag.Var(claims, "claim", "Add claim \"key,value\"")

	flag.Parse()

	publicKey := readPublicKey(*publicKeyFile)

	testament := hippo.NewTestament(*subjectId, *publicKey)
	testament.Claims = claims

	signer := makeSigner(*signingKeyFile)
	decl := sign(*certId, testament, signer)

	cert := &hippo.Certificate{
		Declarations: hippo.Chain{decl},
	}

	writeCert(cert, *outFile)

}

func readPublicKey(filename string) *hippo.PublicKey {
	task := logberry.Main.Task("Read public key", logberry.D{"filename": filename})
	key, err := hippo.PublicKeyFromFile(filename)
	if err != nil {
		task.Fatal(err)
	}
	task.Success()
	return key
}

func readPrivateKey(filename string) *hippo.PrivateKey {
	task := logberry.Main.Task("Read private key", logberry.D{"filename": filename})
	key, err := hippo.PrivateKeyFromFile(filename)
	if err != nil {
		task.Fatal(err)
	}
	task.Success()
	return key
}

func makeSigner(filename string) hippo.Credentials {
	task := logberry.Main.Task("Load signer", logberry.D{"filename": filename})
	credentials, err := hippo.NewSigner(*readPrivateKey(filename))
	if err != nil {
		task.Fatal(err)
	}
	task.Success()
	return credentials
}

func sign(id string, testament *hippo.Testament, signer hippo.Credentials) *hippo.Declaration {
	task := logberry.Main.Task("Sign certificate", logberry.D{"id": id})
	decl, err := testament.Sign(id, signer)
	if err != nil {
		task.Fatal(err)
	}
	task.Success()
	return decl
}

func writeCert(cert *hippo.Certificate, filename string) {

	task := logberry.Main.Task("Write certificate")

	bytes, err := json.Marshal(cert)
	if err != nil {
		task.DieFatal("Failed to marshal certificate", err)
	}

	err = ioutil.WriteFile(filename, bytes, 0644)
	if err != nil {
		task.Fatal(err)
	}

	task.Success()

}
