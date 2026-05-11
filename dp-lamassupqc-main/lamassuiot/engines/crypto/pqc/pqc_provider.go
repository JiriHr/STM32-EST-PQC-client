package pqc

import (
	//"crypto"
	"errors"
)

type Algorithm string

const (
	Dilithium2 Algorithm = "dilithium2" // NIST Level 2
	Dilithium3 Algorithm = "dilithium3" // NIST Level 3
	Dilithium5 Algorithm = "dilithium5" // NIST Level 5
	MLDSA44    Algorithm = "mldsa44"    // NIST Level 2
	MLDSA65    Algorithm = "mldsa65"    // NIST Level 3
	MLDSA87    Algorithm = "mldsa87"    // NIST Level 5
)

type KeyPair struct {
	Algorithm  Algorithm
	PublicKey  []byte
	PrivateKey []byte
}

type Provider interface {
	GenerateKeyPair(alg Algorithm) (*KeyPair, error)

	Sign(data []byte, privateKey []byte, alg Algorithm) ([]byte, error)

	Verify(data []byte, signature []byte, publicKey []byte, alg Algorithm) (bool, error)

	PublicKeySize(alg Algorithm) int
	PrivateKeySize(alg Algorithm) int
	SignatureSize(alg Algorithm) int
}

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrInvalidKeySize       = errors.New("invalid key size")
	ErrSignatureFailed      = errors.New("signature generation failed")
	ErrVerificationFailed   = errors.New("signature verification failed")
)
