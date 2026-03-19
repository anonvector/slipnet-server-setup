package keys

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

// GenerateDNSTTKeys generates a Curve25519 keypair and writes them to files.
// Returns the hex-encoded public key.
func GenerateDNSTTKeys(privKeyPath, pubKeyPath string) (string, error) {
	// Generate random private key
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", fmt.Errorf("generate private key: %w", err)
	}

	// Clamp private key for Curve25519
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	// Derive public key
	pubKey, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}

	// Write private key (hex)
	privHex := hex.EncodeToString(privKey[:])
	if err := os.WriteFile(privKeyPath, []byte(privHex+"\n"), 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	// Write public key (hex)
	pubHex := hex.EncodeToString(pubKey)
	if err := os.WriteFile(pubKeyPath, []byte(pubHex+"\n"), 0644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}

	return pubHex, nil
}

// ImportDNSTTKeys validates a hex-encoded private key, derives its public key,
// and writes both to files. Returns the hex-encoded public key.
func ImportDNSTTKeys(privKeyHex, privKeyPath, pubKeyPath string) (string, error) {
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key hex: %w", err)
	}
	if len(privBytes) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes, got %d", len(privBytes))
	}

	// Derive public key
	pubKey, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}

	// Write private key (hex)
	if err := os.WriteFile(privKeyPath, []byte(privKeyHex+"\n"), 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	// Write public key (hex)
	pubHex := hex.EncodeToString(pubKey)
	if err := os.WriteFile(pubKeyPath, []byte(pubHex+"\n"), 0644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}

	return pubHex, nil
}

// ImportDNSTTKeyPair validates a hex-encoded private and public key pair,
// verifies they match, and writes both to files. Returns the hex-encoded public key.
func ImportDNSTTKeyPair(privKeyHex, pubKeyHex, privKeyPath, pubKeyPath string) (string, error) {
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key hex: %w", err)
	}
	if len(privBytes) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes, got %d", len(privBytes))
	}

	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid public key hex: %w", err)
	}
	if len(pubBytes) != 32 {
		return "", fmt.Errorf("public key must be 32 bytes, got %d", len(pubBytes))
	}

	// Derive expected public key from private key
	derivedPub, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}

	if hex.EncodeToString(derivedPub) != pubKeyHex {
		return "", fmt.Errorf("public key does not match private key")
	}

	// Write private key (hex)
	if err := os.WriteFile(privKeyPath, []byte(privKeyHex+"\n"), 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	// Write public key (hex)
	if err := os.WriteFile(pubKeyPath, []byte(pubKeyHex+"\n"), 0644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}

	return pubKeyHex, nil
}

// ReadPublicKey reads a hex-encoded public key file.
func ReadPublicKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data[:len(data)-1]), nil // trim newline
}
