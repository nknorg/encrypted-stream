package stream

import (
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

// XSalsa20Poly1305Cipher is a AEAD cipher that uses XSalsa20 and Poly1305 to
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

// overhead returns XSalsa20Poly1305Cipher's overhead.
func (c *XSalsa20Poly1305Cipher) overhead() int {
	return 24 + secretbox.Overhead
}

// MaxOverhead implements Cipher.
func (c *XSalsa20Poly1305Cipher) MaxOverhead() int {
	return c.overhead()
}
