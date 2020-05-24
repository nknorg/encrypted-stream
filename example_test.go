package stream_test

import (
	"crypto/rand"
	"net"

	stream "github.com/nknorg/encrypted-stream"
)

func Example() {
	// We use a net.Conn as an example.
	conn, err := net.Dial("tcp", "golang.org:80")
	if err != nil {
		panic(err)
	}

	// In this example we treat key as a prior knowledge. If you use public-key
	// cryptography, you can to do key exchange here using the original stream
	// (e.g. alice sends her public key to bob given that she already know bob's
	// public key) before creating encrypted stream from it.
	var key [32]byte
	_, err = rand.Read(key[:])
	if err != nil {
		panic(err)
	}

	config := &stream.Config{
		Cipher: stream.NewXSalsa20Poly1305Cipher(&key),
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
