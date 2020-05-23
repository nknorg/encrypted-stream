package stream

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize   = 32
	nonceSize = 24
)

func encrypt(ciphertext, plaintext []byte, key [keySize]byte) ([]byte, error) {
	var nonce [nonceSize]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	copy(ciphertext[:nonceSize], nonce[:])
	encrypted := secretbox.Seal(ciphertext[nonceSize:nonceSize], plaintext, &nonce, &key)

	return ciphertext[:nonceSize+len(encrypted)], nil
}

func decrypt(plaintext, ciphertext []byte, key [keySize]byte) ([]byte, error) {
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
}

func createEncryptedStreamPair(alice, bob io.ReadWriter) (*EncryptedStream, *EncryptedStream, error) {
	var key [keySize]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, nil, err
	}

	config := &Config{
		MaxEncryptOverhead: secretbox.Overhead + nonceSize,
		EncryptFunc: func(ciphertext, plaintext []byte) ([]byte, error) {
			return encrypt(ciphertext, plaintext, key)
		},
		DecryptFunc: func(plaintext, ciphertext []byte) ([]byte, error) {
			return decrypt(plaintext, ciphertext, key)
		},
	}

	aliceEncrypted, err := NewEncryptedStream(alice, config)
	if err != nil {
		return nil, nil, err
	}

	bobEncrypted, err := NewEncryptedStream(bob, config)
	if err != nil {
		return nil, nil, err
	}

	return aliceEncrypted, bobEncrypted, nil
}

func read(r io.Reader, expected []byte) error {
	received := make([]byte, len(expected))
	_, err := io.ReadFull(r, received)
	if err != nil {
		return err
	}
	if bytes.Compare(received, expected) != 0 {
		return errors.New("data received is different from expected")
	}
	return nil
}

func write(w io.Writer, data []byte) error {
	_, err := io.Copy(w, bytes.NewReader(data))
	return err
}

func readWriteTest(alice, bob io.ReadWriteCloser) error {
	aliceToBobData := make([]byte, 1<<20)
	_, err := rand.Read(aliceToBobData)
	if err != nil {
		return err
	}

	bobToAliceData := make([]byte, 1<<20)
	_, err = rand.Read(bobToAliceData)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	errChan := make(chan error)

	wg.Add(1)
	go func() {
		defer wg.Done()
		errChan <- write(alice, aliceToBobData)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errChan <- write(bob, bobToAliceData)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errChan <- read(alice, bobToAliceData)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errChan <- read(bob, aliceToBobData)
	}()

	go func() {
		wg.Wait()
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	if err := alice.Close(); err != nil {
		return err
	}

	if err := bob.Close(); err != nil {
		return err
	}

	return nil
}

func readWriteBenchmark(b *testing.B, r io.Reader, w io.Writer) {
	bufSize := 128 * 1024
	wBuf := make([]byte, bufSize)
	rBuf := make([]byte, bufSize)
	b.SetBytes(int64(bufSize))
	b.ResetTimer()
	b.ReportAllocs()

	go func() {
		for i := 0; i < b.N; i++ {
			w.Write(wBuf)
		}
	}()

	var err error
	for bytesRead, n := 0, 0; bytesRead < bufSize*b.N; bytesRead += n {
		n, err = r.Read(rBuf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

type readeWriteCloser struct {
	io.Reader
	io.Writer
	io.Closer
}

func createPipe(encrypted bool) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
	aliceReader, bobWriter := io.Pipe()
	bobReader, aliceWriter := io.Pipe()
	alice := &readeWriteCloser{Reader: aliceReader, Writer: aliceWriter, Closer: aliceWriter}
	bob := &readeWriteCloser{Reader: bobReader, Writer: bobWriter, Closer: bobWriter}

	if encrypted {
		return createEncryptedStreamPair(alice, bob)
	}

	return alice, bob, nil
}

func createTCPConn(encrypted bool) (net.Conn, net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}

	connChan := make(chan net.Conn)
	errChan := make(chan error)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		connChan <- conn
	}()

	alice, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	var bob net.Conn
	select {
	case bob = <-connChan:
	case err := <-errChan:
		return nil, nil, err
	}

	if encrypted {
		return createEncryptedStreamPair(alice, bob)
	}

	return alice, bob, nil
}

func TestPipe(t *testing.T) {
	alice, bob, err := createPipe(true)
	if err != nil {
		t.Fatal(err)
	}

	err = readWriteTest(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTCP(t *testing.T) {
	alice, bob, err := createTCPConn(true)
	if err != nil {
		t.Fatal(err)
	}

	err = readWriteTest(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkPipe(b *testing.B) {
	alice, bob, err := createPipe(true)
	if err != nil {
		b.Fatal(err)
	}

	readWriteBenchmark(b, alice, bob)
}

func BenchmarkTCP(b *testing.B) {
	alice, bob, err := createTCPConn(true)
	if err != nil {
		b.Fatal(err)
	}

	readWriteBenchmark(b, alice, bob)
}
