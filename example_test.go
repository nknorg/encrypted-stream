package stream_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"

	stream "github.com/nknorg/encrypted-stream"
	"golang.org/x/crypto/nacl/secretbox"
)

func Example() {
	// We will use nacl secretbox (XSalsa20 + Poly1305) in this example. You are
	// free to choose any symmetric encryption algorithm or AEAD, or asymmetric
	const (
		keySize   = 32
		nonceSize = 24
	)

	// We use a net.Conn as an example.
	conn, err := net.Dial("tcp", "golang.org:80")
	if err != nil {
		panic(err)
	}

	// In this example we treat key as a prior knowledge. If you use public-key
	// cryptography, you can to do key exchange here using the original stream
	// (e.g. alice sends her public key to bob given that she already know bob's
	// public key) before creating encrypted stream from it.

	// In this example we use a fixed key.
	var key [keySize]byte
	_, err = rand.Read(key[:])
	if err != nil {
		panic(err)
	}

	config := &stream.Config{
		// Provide the encryption function.
		EncryptFunc: func(ciphertext, plaintext []byte) ([]byte, error) {
			var nonce [nonceSize]byte
			_, err := rand.Read(nonce[:])
			if err != nil {
				return nil, err
			}

			copy(ciphertext[:nonceSize], nonce[:])
			encrypted := secretbox.Seal(ciphertext[nonceSize:nonceSize], plaintext, &nonce, &key)

			return ciphertext[:nonceSize+len(encrypted)], nil
		},
		// Provide the decryption function.
		DecryptFunc: func(plaintext, ciphertext []byte) ([]byte, error) {
			if len(ciphertext) <= nonceSize {
				return nil, fmt.Errorf("invalid ciphertext size %d", len(ciphertext))
			}

			var nonce [nonceSize]byte
			copy(nonce[:], ciphertext[:nonceSize])

			plaintext, ok := secretbox.Open(plaintext[:0], ciphertext[nonceSize:], &nonce, &key)
			if !ok {
				return nil, errors.New("decrypt failed")
			}

			return plaintext, nil
		},
		// We simply prepend nonce to the encrypted data, so overhead is encryption
		// overhead (16 bytes) + nonce size (24 bytes).
		MaxEncryptOverhead: secretbox.Overhead + nonceSize,
	}

	// Create an encrypted stream from a conn.
	encryptedConn, err := stream.NewEncryptedStream(conn, config)
	if err != nil {
		panic(err)
	}

	// Now you can use encryptedConn just like a regular conn
	_, err = encryptedConn.Write([]byte("hello world"))
	if err != nil {
		panic(err)
	}
}
