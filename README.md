# HippoCrypto <img src="https://raw.githubusercontent.com/BellerophonMobile/hippo/master/docs/hippocrypto.png" height="64" title="HippoCrypto" alt="Cartoon of a hippopotamus." />

HippoCrypto wraps cryptography functions from Go stdlib and other
packages, and provides a simple chained certificate.

Why?

 * To have transparent algorithm selection and a uniform
   signing/verification interface.
 * To have simple tokens that include certificate chains.
 
[![Build Status](https://travis-ci.org/BellerophonMobile/hippo.svg?branch=master)](https://travis-ci.org/BellerophonMobile/hippo?branch=master) [![GoDoc](https://godoc.org/github.com/BellerophonMobile/hippo?status.svg)](https://godoc.org/github.com/BellerophonMobile/hippo) 

## Wrapper

The core of HippoCrypto is a simple wrapper for cryptographically
signing and verifying data.  The Go APIs for these tasks are a bit
inconsistent in places, so Hippo smooths them over.  In doing so it
provides a very easy way for programs to transparently parameterize
algorithm selection.

The current focii and baked-in algorithms are ECDSA-P256 and Ed25519.
Other algorithms and options for them can easily be incorporated
though.  Please make a suggestion or pull request if you need
something else, but your programs can also easily wrap and register
other algorithms or parameterizations.  These two selections are just
what us maintainers ([Bellerophon
Mobile](https://bellerophonmobile.com/)) are using in our projects, so
they got first attention.

Notably, the ECDSA wrapper has been implemented to be readily
compatible with exporting and importing keys to/from the [HTML5
WebCrypto JavaScript
API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

## Certificates

In addition, HippoCrypto provides a simple digital certificate format
built on its underlying digital signatures wrapper.  These
certificates are much like [JSON Web Tokens (JWT)](https://jwt.io/),
except they readily support chaining: A certificate is a list of
declarations (identity and claims) each signed by some entity in turn
supported by its own declaration, presumably leading back to some root
authority known and trusted by the program testing the certificate.
In this sense they are also similar to [X509
certificates](https://en.wikipedia.org/wiki/X.509), but much simpler
and particularly easier to work with in a Web/JavaScript environment.

## Examples

Here is a trivial example of generating a key, signing some data,
marshaling a key to be shared, and then verifying the data from the
unmarshaled key:

```go
	// Generate a key
	sender, err := Generate("ed25519")
	if err != nil { panic(err) }

	// Sign some data with that key
	data := []byte("Four score and seven years ago")	
	signature, err := sender.Sign(data)
	if err != nil { panic(err) }

	// Marshal the key to JSON to share it somehow
	sharedkey, err := json.Marshal(sender.PublicKey())
	if err != nil { panic(err) }

	// Receive a shared key as JSON and unmarshal
	publickey := PublicKey{}
	err = json.Unmarshal(sharedkey, &publickey)
	if err != nil { panic(err) }

	// Turn the key into an actionable verifier (before this it's just
	// data, the Verifier is an object with specific crypto methods)
	verifier, err := NewVerifier(publickey)
	if err != nil { panic(err) }

	// Verify that this key did sign the data
	err = verifier.Verify(data, signature)
	if err != nil { panic(err) }

	fmt.Printf("Verified")
```

This longer example shows a root CA generating a valid certificate for
an intermediary CA, which generates a valid certificate for a
secondary CA, which in turn generates a valid certificate for a user
that is verified against a pool including the root CA:

```go
	// Create some keys
	user, err := Generate(AlgorithmEd25519)
	if err != nil { panic(err) }

	ca1, err := Generate(AlgorithmECDSA_P256)
	if err != nil { panic(err) }

	ca2, err := Generate(AlgorithmECDSA_P256)
	if err != nil { panic(err) }

	root, err := Generate(AlgorithmEd25519)
	if err != nil { panic(err) }

	// Root makes a certificate for CA1
	ca1_id := NewTestament("ca1", ca1.PublicKey(), Claims{"CertificateAuthority": true})

	ca1_cert, err := ca1_id.Sign("root", root)
	if err != nil { panic(err) }

	// CA1 makes a certificate for CA2
	ca2_id := NewTestament("ca2", ca2.PublicKey(), Claims{"CertificateAuthority": true})

	ca2_cert, err := ca2_id.Sign("ca1", ca1)
	if err != nil { panic(err) }

	// CA2 makes a certificate for the user
	user_id := NewTestament("Joe", user.PublicKey(), nil)

	user_cert, err := user_id.Sign("ca2", ca2)
	if err != nil { panic(err) }

	// Put them together to make a certificate
	out_certificate := &Certificate{Chain{user_cert, ca2_cert, ca1_cert}}

	// Marshal to JSON to share the certificate somehow
	bytes, err := out_certificate.ToBytes()
	if err != nil { panic(err) }

	// Unmarshal the shared certificate
	var in_certificate Certificate
	err = json.Unmarshal(bytes, &in_certificate)
	if err != nil { panic(err) }

	// Create a pool comprised of the root
	pool := NewVerifierPool()

	err = pool.Add("root", root)
	if err != nil { panic(err) }

	// Verify the certificate against the pool
	err = pool.Verify(&in_certificate)
	if err != nil { panic(err) }

	fmt.Println("Verified")
```

## Utilities

Two command line utilities are also provided for convenience:

 * cmd/mkkey generates Hippo-formatted keys in JSON.
 * cmd/mkcert generates Hippo certificates in JSON.

### mkkey

The mkkey utility has two optional parameters:

 * `-algorithm <string>` --- Algorithm to use. (default "ed25519")
 * `-prefix <string>` --- Key filename prefix to use. (default "key")

It generates a key of the given algorithm in the files prefix.public
and prefix.private, e.g.:

```
% ./bin/mkkey -prefix=root
% cat root.public
{"Algorithm":"ed25519","Public":"VSbwTnF7vyK3QpQrVZ0p2KQGuP1XUl6fTUxcKMbzu0o="}
% cat root.private
{"Algorithm":"ed25519","Private":"Z9H_z4y9wq4K_7fg8MqPH6Pzt7nBul2N0E7DCAnbqptVJvBOcXu_IrdClCtVnSnYpAa4_VdSXp9NTFwoxvO7Sg=="}
```

### mkcert

The mkcert utility has several options:

 * `-chain <string>` --- Add chained certificates from given file (optional); may be invoked multiple times.
 * `-claim <value>` --- Add claim "key,value" (optional); may be invoked multiple times. (default {})
 * `-subjectid <string>` --- Subject ID (optional).
 * `-subjectkey <string>` --- Subject public key (required).
 * `-signerid <string>` --- Signer ID (optional).
 * `-signingkey <string>` --- Signing private key (required).
 * `-out <string>` --- Output certificate (required).

It takes the subject's public key (its provable identity), signs it with the
given signing key (the CA's key), and generates a certificate, e.g.:

```
% ./bin/mkcert -subjectid "tjkopena" -subjectkey user.public -signerid="root" -signingkey root.private -out user.cert
% cat user.cert
{"Declarations":[{"Claim":"eyJJRCI6IiIsIlN1YmplY3QiOnsiSUQiOiJ0amtvcGVuYSIsIlB1YmxpY0tleSI6eyJBbGdvcml0aG0iOiJlY2RzYS1wMjU2IiwiUHVibGljIjp7IlgiOiJkNUN3STFFdWJVdUxHWjNYd19EeklFRmlnSFY1U1otM28yUERnSUVxNFBFIiwiWSI6InpKVm5GeDdKQ0loMlhQTmhNNHZZN0RSeTRmWWljSFVPNGc2N3F6YmlpajQifX19LCJDbGFpbXMiOnt9LCJFeHBpcmVzIjoiIn0=","Signer":"root","Signature":"+jw89RLk3Wg9zfhANhfffN3/1yIWmvkPsYyQGc/NDckaF520th0b8iX1mZC6/Si4d3tHDJA3LJZ2Co4yT0nnBA=="}]}
```

The other options enable the subject and signer to be given string
identifiers, arbitrary key/value claims to be made about the subject,
and a chain of additional certificates to be attached supporting the
CA's validity.

Detailed documentation is available in the [GoDocs](https://godoc.org/github.com/BellerophonMobile/hippo).

## License

HippoCrypto is provided under the open source
[MIT license](http://opensource.org/licenses/MIT):

> The MIT License (MIT)
>
> Copyright (c) 2016, 2017 [Bellerophon Mobile](http://bellerophonmobile.com/)
> 
>
> Permission is hereby granted, free of charge, to any person
> obtaining a copy of this software and associated documentation files
> (the "Software"), to deal in the Software without restriction,
> including without limitation the rights to use, copy, modify, merge,
> publish, distribute, sublicense, and/or sell copies of the Software,
> and to permit persons to whom the Software is furnished to do so,
> subject to the following conditions:
>
> The above copyright notice and this permission notice shall be
> included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
> EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
> MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
> NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
> BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
> ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
> CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## Icon

The hippopotamus cartoon icon is by [Harry Cox/AnimalsClipArt.com](http://animalsclipart.com/hippopotamus-cartoon-character/), released under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
