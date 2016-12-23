package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/BellerophonMobile/hippo"
	"github.com/BellerophonMobile/logberry"
)

type claims hippo.Claims

func (c claims) String() string {
	bytes, _ := json.Marshal(c)
	return string(bytes)
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
		return fmt.Errorf("Invalid claim value format: %s", err)
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

type chain hippo.Chain

func (c *chain) String() string {
	bytes, _ := json.Marshal(c)
	return string(bytes)
}

func (c *chain) Set(flag string) error {
	cert, err := hippo.CertificateFromFile(flag)
	if err != nil {
		return err
	}

	*c = append(*c, cert.Declarations...)

	return nil
}

func main() {
	defer logberry.Std.Stop()

	certId := flag.String("certid", "", "Certificate ID.")
	subjectId := flag.String("subjectid", "", "Subject ID.")
	publicKeyFile := flag.String("subjectkey", "", "Subject public key.")
	signingKeyFile := flag.String("signingkey", "", "Signing private key.")
	outFile := flag.String("out", "", "Output certificate.")

	claims := make(claims)
	var chain chain

	flag.Var(claims, "claim", "Add claim \"key,value\".")
	flag.Var(&chain, "chain", "Add chained certificates.")

	flag.Parse()

	publicKey,err := readPublicKey(*publicKeyFile)
	if err != nil {
		return
	}
	
	testament := hippo.NewTestament(*subjectId, *publicKey, hippo.Claims(claims))

	signer,err := makeSigner(*signingKeyFile)
	if err != nil {
		return
	}

	decl,err := sign(*certId, testament, signer)
	if err != nil {
		return
	}

	cert := &hippo.Certificate{Declarations: hippo.Chain{decl}}
	cert.Declarations = append(cert.Declarations, chain...)

	writeCert(cert, *outFile)
	if err != nil {
		return
	}

}

func readPublicKey(filename string) (*hippo.PublicKey,error) {
	task := logberry.Main.Task("Read public key", logberry.D{"filename": filename})
	key, err := hippo.PublicKeyFromFile(filename)
	if err != nil {
		return nil,task.Error(err)
	}
	
	return key,task.Success()
}

func readPrivateKey(filename string) (*hippo.PrivateKey,error) {
	task := logberry.Main.Task("Read private key", logberry.D{"filename": filename})
	key, err := hippo.PrivateKeyFromFile(filename)
	if err != nil {
		return nil,task.Error(err)
	}
	
	return key,task.Success()
}

func makeSigner(filename string) (hippo.Credentials,error) {
	task := logberry.Main.Task("Load signer", logberry.D{"filename": filename})

	privkey,err := readPrivateKey(filename)
	if err != nil {
		return nil,task.Error(err)
	}

	credentials, err := hippo.NewSigner(*privkey)
	if err != nil {
		return nil,task.Error(err)
	}
	
	return credentials,task.Success()
}

func sign(id string, testament *hippo.Testament, signer hippo.Credentials) (*hippo.Declaration,error) {
	task := logberry.Main.Task("Sign certificate", logberry.D{"id": id})
	decl, err := testament.Sign(id, signer)
	if err != nil {
		return nil,task.Error(err)
	}
	
	return decl,task.Success()
}

func writeCert(cert *hippo.Certificate, filename string) error {
	task := logberry.Main.Task("Write certificate")
	err := cert.ToFile(filename)
	if err != nil {
		return task.Error(err)
	}
	return task.Success()
}
