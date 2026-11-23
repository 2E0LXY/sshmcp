package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
)

// Vault encrypts stored SSH credentials with AES-256-GCM. The key lives in a
// separate 0600 file, so a copied database alone does not expose passwords.
type Vault struct{ aead cipher.AEAD }

var vault *Vault

func loadVault(keyFile string) (*Vault, error) {
	key, err := os.ReadFile(keyFile)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyFile, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("master key file must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead}, nil
}

func (v *Vault) Seal(plain string) (string, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(v.aead.Seal(nonce, nonce, []byte(plain), nil)), nil
}

func (v *Vault) Open(enc string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(raw) < v.aead.NonceSize() {
		return "", errors.New("corrupt secret")
	}
	n := v.aead.NonceSize()
	plain, err := v.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", errors.New("cannot decrypt secret (wrong master key?)")
	}
	return string(plain), nil
}
