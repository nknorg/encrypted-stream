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
)

const (
	xsalsa20poly1305 = iota
	aesgcm128
	aesgcm256
)

func createEncryptedStreamPair(alice, bob io.ReadWriter, cipherID int) (*EncryptedStream, *EncryptedStream, error) {
	var cipher Cipher
	switch cipherID {
	case xsalsa20poly1305:
		var key [32]byte
		_, err := rand.Read(key[:])
		if err != nil {
			return nil, nil, err
		}
		cipher = NewXSalsa20Poly1305Cipher(&key)
	case aesgcm128:
		key := make([]byte, 16)
		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
		cipher, err = NewAESGCMCipher(key)
		if err != nil {
			return nil, nil, err
		}
	case aesgcm256:
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
		cipher, err = NewAESGCMCipher(key)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("unknown cipher %v", cipherID)
	}

	aliceEncrypted, err := NewEncryptedStream(alice, &Config{
		Cipher:          cipher,
		SequentialNonce: true,
		Initiator:       true,
	})
	if err != nil {
		return nil, nil, err
	}

	bobEncrypted, err := NewEncryptedStream(bob, &Config{
		Cipher:          cipher,
		SequentialNonce: true,
	})
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

func createPipe(encrypted bool, cipherID int) (io.ReadWriteCloser, io.ReadWriteCloser, error) {
	aliceReader, bobWriter := io.Pipe()
	bobReader, aliceWriter := io.Pipe()
	alice := &readeWriteCloser{Reader: aliceReader, Writer: aliceWriter, Closer: aliceWriter}
	bob := &readeWriteCloser{Reader: bobReader, Writer: bobWriter, Closer: bobWriter}

	if encrypted {
		return createEncryptedStreamPair(alice, bob, cipherID)
	}

	return alice, bob, nil
}

func createTCPConn(encrypted bool, cipherID int) (net.Conn, net.Conn, error) {
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
		return createEncryptedStreamPair(alice, bob, cipherID)
	}

	return alice, bob, nil
}

func TestPipeXSalsa20Poly1305(t *testing.T) {
	alice, bob, err := createPipe(true, xsalsa20poly1305)
	if err != nil {
		t.Fatal(err)
	}

	err = readWriteTest(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPipeAESGCM128(t *testing.T) {
	alice, bob, err := createPipe(true, aesgcm128)
	if err != nil {
		t.Fatal(err)
	}

	err = readWriteTest(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPipeAESGCM256(t *testing.T) {
	alice, bob, err := createPipe(true, aesgcm256)
	if err != nil {
		t.Fatal(err)
	}

	err = readWriteTest(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTCPXSalsa20Poly1305(t *testing.T) {
	alice, bob, err := createTCPConn(true, xsalsa20poly1305)
	if err != nil {
		t.Fatal(err)
	}

	err = readWriteTest(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTCPAESGCM128(t *testing.T) {
	alice, bob, err := createTCPConn(true, aesgcm128)
	if err != nil {
		t.Fatal(err)
	}

	err = readWriteTest(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTCPAESGCM256(t *testing.T) {
	alice, bob, err := createTCPConn(true, aesgcm256)
	if err != nil {
		t.Fatal(err)
	}

	err = readWriteTest(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkPipeXSalsa20Poly1305(b *testing.B) {
	alice, bob, err := createPipe(true, xsalsa20poly1305)
	if err != nil {
		b.Fatal(err)
	}
	readWriteBenchmark(b, alice, bob)
}

func BenchmarkPipeAESGCM128(b *testing.B) {
	alice, bob, err := createPipe(true, aesgcm128)
	if err != nil {
		b.Fatal(err)
	}
	readWriteBenchmark(b, alice, bob)
}

func BenchmarkPipeAESGCM256(b *testing.B) {
	alice, bob, err := createPipe(true, aesgcm256)
	if err != nil {
		b.Fatal(err)
	}
	readWriteBenchmark(b, alice, bob)
}

func BenchmarkTCPXSalsa20Poly1305(b *testing.B) {
	alice, bob, err := createTCPConn(true, xsalsa20poly1305)
	if err != nil {
		b.Fatal(err)
	}
	readWriteBenchmark(b, alice, bob)
}

func BenchmarkTCPAESGCM128(b *testing.B) {
	alice, bob, err := createTCPConn(true, aesgcm128)
	if err != nil {
		b.Fatal(err)
	}
	readWriteBenchmark(b, alice, bob)
}

func BenchmarkTCPAESGCM256(b *testing.B) {
	alice, bob, err := createTCPConn(true, aesgcm256)
	if err != nil {
		b.Fatal(err)
	}
	readWriteBenchmark(b, alice, bob)
}
