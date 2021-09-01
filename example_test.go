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

	// In this example we treat key as a prior knowledge. In actual usage you can
	// do handshake here using the original stream and compute shared key before
	// creating encrypted stream from it.
	var key [32]byte
	_, err = rand.Read(key[:])
	if err != nil {
		panic(err)
	}

	config := &stream.Config{
		Cipher:          stream.NewXSalsa20Poly1305Cipher(&key),
		SequentialNonce: true, // only when key is unique for every stream
		Initiator:       true, // only on the dialer side
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
