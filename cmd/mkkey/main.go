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
	algorithm := flag.String("algorithm", "ed25519", "Algorithm to use.")
	prefix := flag.String("prefix", "key", "Key filename prefix to use.")

	flag.Parse()

	keys := generateKeys(*algorithm)
	writeKeys(keys, *prefix)
}

func generateKeys(algorithm string) hippo.Credentials {
	task := logberry.Main.Task("Generate keys")
	keys, err := hippo.Generate(algorithm)
	if err != nil {
		task.Fatal(err)
	}
	task.Success()

	return keys
}

func writeKeys(keys hippo.Credentials, prefix string) {
	var err error

	publicFile := prefix + ".public"
	privateFile := prefix + ".private"

	task := logberry.Main.Task("Write keys", logberry.D{
		"public":  publicFile,
		"private": privateFile,
	})

	err = keys.PublicKey().ToFile(publicFile)
	if err != nil {
		task.DieFatal("Failed to write public key", err)
	}

	err = keys.PrivateKey().ToFile(privateFile)
	if err != nil {
		task.DieFatal("Failed to write private key", err)
	}

	task.Success()
}
