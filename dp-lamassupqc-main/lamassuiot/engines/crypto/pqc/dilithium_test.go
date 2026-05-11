package pqc_test

import (
	"crypto/rand"
	"testing"

	"github.com/lamassuiot/lamassuiot/engines/crypto/pqc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDilithiumKeyGeneration(t *testing.T) {
	provider := pqc.NewDilithiumProvider()

	tests := []struct {
		name      string
		algorithm pqc.Algorithm
	}{
		{"Dilithium2", pqc.Dilithium2},
		{"Dilithium3", pqc.Dilithium3},
		{"Dilithium5", pqc.Dilithium5},
		{"MLDSA44", pqc.MLDSA44},
		{"MLDSA65", pqc.MLDSA65},
		{"MLDSA87", pqc.MLDSA87},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := provider.GenerateKeyPair(tt.algorithm)
			require.NoError(t, err)
			assert.NotNil(t, keyPair)
			assert.Equal(t, tt.algorithm, keyPair.Algorithm)
			assert.NotEmpty(t, keyPair.PublicKey)
			assert.NotEmpty(t, keyPair.PrivateKey)
			assert.Equal(t, provider.PublicKeySize(tt.algorithm), len(keyPair.PublicKey))
			assert.Equal(t, provider.PrivateKeySize(tt.algorithm), len(keyPair.PrivateKey))
		})
	}
}

func TestDilithiumSignAndVerify(t *testing.T) {
	provider := pqc.NewDilithiumProvider()

	tests := []struct {
		name      string
		algorithm pqc.Algorithm
	}{
		{"Dilithium2", pqc.Dilithium2},
		{"Dilithium3", pqc.Dilithium3},
		{"Dilithium5", pqc.Dilithium5},
		{"MLDSA44", pqc.MLDSA44},
		{"MLDSA65", pqc.MLDSA65},
		{"MLDSA87", pqc.MLDSA87},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate key pair
			keyPair, err := provider.GenerateKeyPair(tt.algorithm)
			require.NoError(t, err)

			// Test data
			data := []byte("Hello, Post-Quantum World!")

			// Sign
			signature, err := provider.Sign(data, keyPair.PrivateKey, tt.algorithm)
			require.NoError(t, err)
			assert.NotEmpty(t, signature)
			assert.Equal(t, provider.SignatureSize(tt.algorithm), len(signature))

			// Verify
			valid, err := provider.Verify(data, signature, keyPair.PublicKey, tt.algorithm)
			require.NoError(t, err)
			assert.True(t, valid)

			// Verify with wrong data
			wrongData := []byte("Wrong data")
			valid, err = provider.Verify(wrongData, signature, keyPair.PublicKey, tt.algorithm)
			require.NoError(t, err)
			assert.False(t, valid)
		})
	}
}

func BenchmarkDilithium3KeyGeneration(b *testing.B) {
	provider := pqc.NewDilithiumProvider()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.GenerateKeyPair(pqc.Dilithium3)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDilithium3Signing(b *testing.B) {
	provider := pqc.NewDilithiumProvider()
	keyPair, _ := provider.GenerateKeyPair(pqc.Dilithium3)
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.Sign(data, keyPair.PrivateKey, pqc.Dilithium3)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDilithium3Verification(b *testing.B) {
	provider := pqc.NewDilithiumProvider()
	keyPair, _ := provider.GenerateKeyPair(pqc.Dilithium3)
	data := make([]byte, 1024)
	rand.Read(data)
	signature, _ := provider.Sign(data, keyPair.PrivateKey, pqc.Dilithium3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.Verify(data, signature, keyPair.PublicKey, pqc.Dilithium3)
		if err != nil {
			b.Fatal(err)
		}
	}
}
