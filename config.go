package stream

import (
	"errors"

	"github.com/imdario/mergo"
)

// EncryptFunc encrypts a plaintext to ciphertext. Returns ciphertext slice
// whose length should be equal to ciphertext length. Input buffer ciphertext
// has enough size for encrypted plaintext, and their size satisfy:
// `len(plaintext) <= config.MaxChunkSize` and `len(ciphertext) ==
// config.MaxChunkSize + config.MaxOverheadSize`.
type EncryptFunc func(ciphertext, plaintext []byte) ([]byte, error)

// DecryptFunc decrypts a ciphertext to plaintext. Returns plaintext slice whose
// length should be equal to plaintext length. Input buffer plaintext has enough
// size for decrypted ciphertext, and their size satisfy: `len(plaintext) ==
// config.MaxChunkSize` and `len(ciphertext) <= config.MaxChunkSize +
// config.MaxOverheadSize`.
type DecryptFunc func(plaintext, ciphertext []byte) ([]byte, error)

// Config is the stream configuration.
type Config struct {
	// EncryptFunc for encrypting buffer.
	EncryptFunc EncryptFunc

	// DecryptFunc for decrypting buffer.
	DecryptFunc DecryptFunc

	// MaxOverheadSize is the max number of bytes overhead of ciphertext compared
	// to plaintext. It is only used to determine internal buffer size, so
	// overestimate is ok. If zero, default value (64) will be used.
	MaxEncryptOverhead int

	// MaxChunkSize is the max number of bytes that will be encrypted and write to
	// underlying stream in a single chunk. If zero, default value (65535) will be
	// used.
	MaxChunkSize int
}

// DefaultConfig returns the default config.
func DefaultConfig() *Config {
	return &Config{
		MaxEncryptOverhead: 64,
		MaxChunkSize:       65535,
	}
}

// Verify checks whether a config is valid.
func (config *Config) Verify() error {
	if config == nil {
		return errors.New("nil config")
	}

	if config.EncryptFunc == nil {
		return errors.New("EncryptFunc should not be nil")
	}

	if config.DecryptFunc == nil {
		return errors.New("DecryptFunc should not be nil")
	}

	if config.MaxEncryptOverhead < 0 {
		return errors.New("MaxEncryptOverhead should not be less than 0")
	}

	if config.MaxChunkSize <= 0 {
		return errors.New("MaxChunkSize should be greater than 0")
	}

	return nil
}

// MergeConfig merges a given config with the default config recursively. Any
// non zero value fields will override the default config.
func MergeConfig(base, conf *Config) (*Config, error) {
	merged := *base
	if conf != nil {
		err := mergo.Merge(&merged, conf, mergo.WithOverride)
		if err != nil {
			return nil, err
		}
	}
	return &merged, nil
}
