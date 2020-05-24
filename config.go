package stream

import (
	"errors"

	"github.com/imdario/mergo"
)

// Config is the configuration for encrypted stream.
type Config struct {
	// Cipher is used to encrypt and decrypt data.
	Cipher Cipher

	// MaxChunkSize is the max number of bytes that will be encrypted and write to
	// underlying stream in a single chunk. If zero, default value (65535) will be
	// used.
	MaxChunkSize int
}

// DefaultConfig returns the default config.
func DefaultConfig() *Config {
	return &Config{
		MaxChunkSize: 65535,
	}
}

// Verify checks whether a config is valid.
func (config *Config) Verify() error {
	if config == nil {
		return errors.New("nil config")
	}

	if config.Cipher.MaxOverhead() < 0 {
		return errors.New("Cipher.MaxOverhead() should not be less than 0")
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
