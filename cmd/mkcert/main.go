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
	c[v[0]] = v[1]
	return nil
}

// mkkey generates public and private keys, respectively
// writing them to files prefix.public and prefix.private, where
// prefix is an input parameter with default "key".
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
	writeCert(decl, *outFile)
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

func writeCert(decl *hippo.Declaration, filename string) {
	task := logberry.Main.Task("Write certificate")

	bytes, err := json.Marshal(decl)
	if err != nil {
		task.DieFatal("Failed to marshal declaration", err)
	}

	err = ioutil.WriteFile(filename, bytes, 0644)
	if err != nil {
		task.Fatal(err)
	}

	task.Success()
}
