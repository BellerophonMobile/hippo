package main

import (
	"flag"

	"github.com/BellerophonMobile/hippo"
	"github.com/BellerophonMobile/logberry"
)

// mkkey generates public and private keys, respectively
// writing them to files prefix.public and prefix.private, where
// prefix is an input parameter with default "key".
func main() {
	defer logberry.Std.Stop()
	
	algorithm := flag.String("algorithm", "ed25519", "Algorithm to use.")
	prefix := flag.String("prefix", "key", "Key filename prefix to use.")

	flag.Parse()

	keys,err := generateKeys(*algorithm)
	if err != nil {
		return
	}
	
	writeKeys(keys, *prefix)
}

func generateKeys(algorithm string) (hippo.Credentials,error) {
	task := logberry.Main.Task("Generate keys")

	keys, err := hippo.GenerateCredentials(algorithm)
	if err != nil {
		return nil,task.Error(err)
	}

	return keys,task.Success()
}

func writeKeys(keys hippo.Credentials, prefix string) error {
	var err error

	publicFile := prefix + ".public"
	privateFile := prefix + ".private"

	task := logberry.Main.Task("Write keys", logberry.D{
		"public":  publicFile,
		"private": privateFile,
	})

	err = keys.PublicKey().ToFile(publicFile)
	if err != nil {
		return task.WrapError("Failed to write public key", err)
	}

	err = keys.PrivateKey().ToFile(privateFile)
	if err != nil {
		return task.WrapError("Failed to write private key", err)
	}

	return task.Success()
}
