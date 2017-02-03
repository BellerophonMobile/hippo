package hippo

// SKCiphers encapsulate a secret key (symmetric) encryption
// algorithm, parameterization, and an associated key.
type SKCipher interface {

	// Key returns a JSON Base64-URL encoded marshaling of the
	// SKCipher's secret key.
	SecretKey() PrivateKey

	// SetKey sets the SKCipher's secret key from the given PrivateKey
	// containing JSON Base64-URL encoded data.
	SetKey(key PrivateKey) error

	// Encrypt produces cipherdata for the given plaindata.
	Encrypt(data []byte) ([]byte, error)

	// Decrypt takes cipherdata and produces plaindata.  N.B.: In
	// general the absence of an error does NOT indicate that the data
	// is valid.  A separate mechanism must be applied to assure
	// integrity and authenticity.  Then note that implementing such a
	// mechanism is not as simple as signing either the plaindata or
	// cipherdata alone.
	Decrypt(data []byte) ([]byte, error)
}
