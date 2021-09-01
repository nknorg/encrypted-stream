package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

// Cipher provides encrypt and decrypt function of a slice data.
type Cipher interface {
	// Encrypt encrypts a plaintext to ciphertext. Returns ciphertext slice
	// whose length should be equal to ciphertext length. Input buffer ciphertext
	// has enough length for encrypted plaintext, and the length satisfy:
	// 	len(ciphertext) == MaxChunkSize + MaxOverheadSize
	// 	len(plaintext) <= MaxChunkSize
	Encrypt(ciphertext, plaintext, nonce []byte) ([]byte, error)

	// Decrypt decrypts a ciphertext to plaintext. Returns plaintext slice
	// whose length should be equal to plaintext length. Input buffer plaintext
	// has enough length for decrypted ciphertext, and the length satisfy:
	//	len(plaintext) == MaxChunkSize
	//	len(ciphertext) <= MaxChunkSize + MaxOverheadSize
	Decrypt(plaintext, ciphertext, nonce []byte) ([]byte, error)

	// MaxOverhead is the max number of bytes overhead of ciphertext compared to
	// plaintext. It is only used to determine internal buffer size, so
	// overestimate is ok.
	MaxOverhead() int

	// NonceSize is the nonce size in bytes.
	NonceSize() int
}

// XSalsa20Poly1305Cipher is an AEAD cipher that uses XSalsa20 and Poly1305 to
// encrypt and authenticate messages. The ciphertext it produces contains 24
// bytes of random nonce, followed by n+16 bytes of authenticated encrypted
// data, where n is the plaintext size.
type XSalsa20Poly1305Cipher struct {
	key *[32]byte
}

// NewXSalsa20Poly1305Cipher creates a XSalsa20Poly1305Cipher with a given key.
// For best security, every stream should have a unique key.
func NewXSalsa20Poly1305Cipher(key *[32]byte) *XSalsa20Poly1305Cipher {
	return &XSalsa20Poly1305Cipher{
		key: key,
	}
}

// Encrypt implements Cipher.
func (c *XSalsa20Poly1305Cipher) Encrypt(ciphertext, plaintext, nonce []byte) ([]byte, error) {
	var n [24]byte
	copy(n[:], nonce[:24])

	encrypted := secretbox.Seal(ciphertext[:0], plaintext, &n, c.key)

	return ciphertext[:len(encrypted)], nil
}

// Decrypt implements Cipher.
func (c *XSalsa20Poly1305Cipher) Decrypt(plaintext, ciphertext, nonce []byte) ([]byte, error) {
	var n [24]byte
	copy(n[:], nonce[:24])

	plaintext, ok := secretbox.Open(plaintext[:0], ciphertext, &n, c.key)
	if !ok {
		return nil, errors.New("decrypt failed")
	}

	return plaintext, nil
}

// overhead returns Cipher's overhead including nonce size.
func (c *XSalsa20Poly1305Cipher) overhead() int {
	return secretbox.Overhead
}

// MaxOverhead implements Cipher.
func (c *XSalsa20Poly1305Cipher) MaxOverhead() int {
	return c.overhead()
}

// NonceSize implements Cipher.
func (c *XSalsa20Poly1305Cipher) NonceSize() int {
	return 24
}

// CryptoAEADCipher is a wrapper to crypto/cipher AEAD interface and implements
// Cipher interface.
type CryptoAEADCipher struct {
	aead cipher.AEAD
}

// NewCryptoAEADCipher converts a crypto/cipher AEAD to Cipher.
func NewCryptoAEADCipher(aead cipher.AEAD) *CryptoAEADCipher {
	return &CryptoAEADCipher{
		aead: aead,
	}
}

// Encrypt implements Cipher.
func (c *CryptoAEADCipher) Encrypt(ciphertext, plaintext, nonce []byte) ([]byte, error) {
	encrypted := c.aead.Seal(ciphertext[:0], nonce, plaintext, nil)
	return ciphertext[:len(encrypted)], nil
}

// Decrypt implements Cipher.
func (c *CryptoAEADCipher) Decrypt(plaintext, ciphertext, nonce []byte) ([]byte, error) {
	plaintext, err := c.aead.Open(plaintext[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %v", err)
	}

	return plaintext, nil
}

// overhead returns Cipher's overhead including nonce size.
func (c *CryptoAEADCipher) overhead() int {
	return c.aead.Overhead()
}

// MaxOverhead implements Cipher.
func (c *CryptoAEADCipher) MaxOverhead() int {
	return c.overhead()
}

// NonceSize implements Cipher.
func (c *CryptoAEADCipher) NonceSize() int {
	return c.aead.NonceSize()
}

// NewAESGCMCipher creates a 128-bit (16 bytes key) or 256-bit (32 bytes key)
// AES block cipher wrapped in Galois Counter Mode with the standard nonce
// length. For best security, every stream should have a unique key.
func NewAESGCMCipher(key []byte) (*CryptoAEADCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return NewCryptoAEADCipher(aesgcm), nil
}
