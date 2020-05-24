package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	Encrypt(ciphertext, plaintext []byte) ([]byte, error)

	// Decrypt decrypts a ciphertext to plaintext. Returns plaintext slice
	// whose length should be equal to plaintext length. Input buffer plaintext
	// has enough length for decrypted ciphertext, and the length satisfy:
	//	len(plaintext) == MaxChunkSize
	//	len(ciphertext) <= MaxChunkSize + MaxOverheadSize
	Decrypt(plaintext, ciphertext []byte) ([]byte, error)

	// MaxOverhead is the max number of bytes overhead of ciphertext compared to
	// plaintext. This should contain both encryption overhead and size of
	// additional data in ciphertext like nonce. It is only used to determine
	// internal buffer size, so overestimate is ok.
	MaxOverhead() int
}

// XSalsa20Poly1305Cipher is an AEAD cipher that uses XSalsa20 and Poly1305 to
// encrypt and authenticate messages. The ciphertext it produces contains 24
// bytes of random nonce, followed by n+16 bytes of authenticated encrypted
// data, where n is the plaintext size.
type XSalsa20Poly1305Cipher struct {
	key *[32]byte
}

// NewXSalsa20Poly1305Cipher creates a XSalsa20Poly1305Cipher with a given key.
func NewXSalsa20Poly1305Cipher(key *[32]byte) *XSalsa20Poly1305Cipher {
	return &XSalsa20Poly1305Cipher{
		key: key,
	}
}

// Encrypt implements Cipher.
func (c *XSalsa20Poly1305Cipher) Encrypt(ciphertext, plaintext []byte) ([]byte, error) {
	_, err := rand.Read(ciphertext[:24])
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])

	encrypted := secretbox.Seal(ciphertext[24:24], plaintext, &nonce, c.key)

	return ciphertext[:24+len(encrypted)], nil
}

// Decrypt implements Cipher.
func (c *XSalsa20Poly1305Cipher) Decrypt(plaintext, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= c.overhead() {
		return nil, fmt.Errorf("invalid ciphertext size %d", len(ciphertext))
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])

	plaintext, ok := secretbox.Open(plaintext[:0], ciphertext[24:], &nonce, c.key)
	if !ok {
		return nil, errors.New("decrypt failed")
	}

	return plaintext, nil
}

// overhead returns Cipher's overhead including nonce size.
func (c *XSalsa20Poly1305Cipher) overhead() int {
	return 24 + secretbox.Overhead
}

// MaxOverhead implements Cipher.
func (c *XSalsa20Poly1305Cipher) MaxOverhead() int {
	return c.overhead()
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
func (c *CryptoAEADCipher) Encrypt(ciphertext, plaintext []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	_, err := rand.Read(ciphertext[:nonceSize])
	if err != nil {
		return nil, err
	}

	encrypted := c.aead.Seal(ciphertext[nonceSize:nonceSize], ciphertext[:nonceSize], plaintext, nil)

	return ciphertext[:nonceSize+len(encrypted)], nil
}

// Decrypt implements Cipher.
func (c *CryptoAEADCipher) Decrypt(plaintext, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= c.overhead() {
		return nil, fmt.Errorf("invalid ciphertext size %d", len(ciphertext))
	}

	plaintext, err := c.aead.Open(plaintext[:0], ciphertext[:c.aead.NonceSize()], ciphertext[c.aead.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %v", err)
	}

	return plaintext, nil
}

// overhead returns Cipher's overhead including nonce size.
func (c *CryptoAEADCipher) overhead() int {
	return c.aead.NonceSize() + c.aead.Overhead()
}

// MaxOverhead implements Cipher.
func (c *CryptoAEADCipher) MaxOverhead() int {
	return c.overhead()
}

// NewAESGCMCipher creates a 128-bit (16 bytes key) or 256-bit (32 bytes key)
// AES block cipher wrapped in Galois Counter Mode with the standard nonce
// length.
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
