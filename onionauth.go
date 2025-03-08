package main

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
)

func keyStr(key []byte) string {
	// Encode the key to base32 with uppercase letters, no padding
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(key)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <name> <onion_address>\n", os.Args[0])
		os.Exit(1)
	}

	name := os.Args[1]
	onionAddress := os.Args[2]

	// Strip the .onion suffix if present
	onionAddress = strings.TrimSuffix(onionAddress, ".onion")

	// Generate private key
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	// Ensure private key follows curve25519 requirements
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Generate public key
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate public key: %v\n", err)
		os.Exit(1)
	}

	// Convert keys to base32 strings
	publicKeyStr := keyStr(publicKey)
	privateKeyStr := keyStr(privateKey)

	// Create the formatted key strings with prefixes
	publicKeyWithPrefix := fmt.Sprintf("descriptor:x25519:%s", publicKeyStr)
	privateKeyWithPrefix := fmt.Sprintf("%s:descriptor:x25519:%s", onionAddress, privateKeyStr)

	// Write public key file
	publicKeyFilename := fmt.Sprintf("%s.auth", name)
	if err := os.WriteFile(publicKeyFilename, []byte(publicKeyWithPrefix), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write public key file: %v\n", err)
		os.Exit(1)
	}

	// Write private key file
	privateKeyFilename := fmt.Sprintf("%s_onion.auth_private", name)
	if err := os.WriteFile(privateKeyFilename, []byte(privateKeyWithPrefix), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write private key file: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Printf("%s public key:  %s\n", name, publicKeyStr)
	fmt.Printf("%s private key: %s\n", name, privateKeyStr)
	fmt.Printf("Public key saved to %s\n", publicKeyFilename)
	fmt.Printf("Private key saved to %s\n", privateKeyFilename)
}
