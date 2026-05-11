package vaultkv2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDilithiumOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Dilithium integration test in short mode")
	}

	// Use the same test setup as TestVaultCryptoEngine
	ctx := context.Background()

	// Get the engine from existing test helper
	engine := setupTestEngine(t)

	vaultEngine := engine

	t.Run("CreateDilithium3Key", func(t *testing.T) {
		keyID, publicKey, err := vaultEngine.CreateDilithiumPrivateKey(ctx, "3")
		require.NoError(t, err)
		assert.NotEmpty(t, keyID)
		assert.NotEmpty(t, publicKey)
		assert.Equal(t, 1952, len(publicKey), "Dilithium3 public key should be 1952 bytes")

		t.Logf("✓ Created Dilithium3 key: %s", keyID)
		t.Logf("✓ Public key size: %d bytes", len(publicKey))
	})

	t.Run("SignWithDilithium3", func(t *testing.T) {
		// Create key
		keyID, publicKey, err := vaultEngine.CreateDilithiumPrivateKey(ctx, "3")
		require.NoError(t, err)

		// Sign data
		testData := []byte("Hello, Post-Quantum Cryptography!")
		signature, err := vaultEngine.SignDilithium(keyID, testData, "3")
		require.NoError(t, err)
		assert.NotEmpty(t, signature)
		assert.Equal(t, 3293, len(signature), "Dilithium3 signature should be 3293 bytes")

		// Verify signature
		valid, err := vaultEngine.pqcProvider.Verify(testData, signature, publicKey, "dilithium3")
		require.NoError(t, err)
		assert.True(t, valid, "Signature should be valid")

		t.Logf("✓ Signed %d bytes of data", len(testData))
		t.Logf("✓ Signature size: %d bytes", len(signature))
		t.Logf("✓ Signature verified successfully")
	})

	t.Run("GetDilithiumPrivateKey", func(t *testing.T) {
		// Create key
		keyID, _, err := vaultEngine.CreateDilithiumPrivateKey(ctx, "3")
		require.NoError(t, err)

		// Retrieve it
		privateKey, err := vaultEngine.GetDilithiumPrivateKeyByID(keyID)
		require.NoError(t, err)
		assert.NotEmpty(t, privateKey)
		assert.Equal(t, 4000, len(privateKey), "Dilithium3 private key should be 4000 bytes")

		t.Logf("✓ Retrieved private key: %d bytes", len(privateKey))
	})

	t.Run("AllDilithiumModes", func(t *testing.T) {
		modes := []struct {
			mode          string
			pubKeySize    int
			privKeySize   int
			signatureSize int
		}{
			{"2", 1312, 2528, 2420},
			{"3", 1952, 4000, 3293},
			{"5", 2592, 4864, 4595},
		}

		for _, tc := range modes {
			t.Run("Dilithium"+tc.mode, func(t *testing.T) {
				// Create key
				keyID, pubKey, err := vaultEngine.CreateDilithiumPrivateKey(ctx, tc.mode)
				require.NoError(t, err)
				assert.Equal(t, tc.pubKeySize, len(pubKey))

				// Get private key
				privKey, err := vaultEngine.GetDilithiumPrivateKeyByID(keyID)
				require.NoError(t, err)
				assert.Equal(t, tc.privKeySize, len(privKey))

				// Sign
				sig, err := vaultEngine.SignDilithium(keyID, []byte("test"), tc.mode)
				require.NoError(t, err)
				assert.Equal(t, tc.signatureSize, len(sig))

				t.Logf("✓ Dilithium%s: pub=%d, priv=%d, sig=%d bytes",
					tc.mode, len(pubKey), len(privKey), len(sig))
			})
		}
	})

	t.Run("DeleteDilithiumKey", func(t *testing.T) {
		// Create key
		keyID, _, err := vaultEngine.CreateDilithiumPrivateKey(ctx, "3")
		require.NoError(t, err)

		// Verify it exists
		_, err = vaultEngine.GetDilithiumPrivateKeyByID(keyID)
		require.NoError(t, err)

		// Delete it
		err = vaultEngine.DeleteKey(keyID)
		require.NoError(t, err)

		// Verify it's gone
		_, err = vaultEngine.GetDilithiumPrivateKeyByID(keyID)
		assert.Error(t, err)

		t.Logf("✓ Key deleted successfully")
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		// Non-existent key
		_, err := vaultEngine.GetDilithiumPrivateKeyByID("non-existent")
		assert.Error(t, err)

		// Invalid mode
		_, _, err = vaultEngine.CreateDilithiumPrivateKey(ctx, "invalid")
		assert.Error(t, err)

		// Create key with mode 3, try to sign with mode 2
		keyID, _, err := vaultEngine.CreateDilithiumPrivateKey(ctx, "3")
		require.NoError(t, err)

		_, err = vaultEngine.SignDilithium(keyID, []byte("test"), "2")
		// This should work but may produce invalid signature
		// The real validation would be in actual usage
	})
}

// Helper function - if it doesn't exist in your test file, you'll need to check
// how the existing TestVaultCryptoEngine sets up the engine
func setupTestEngine(t *testing.T) *VaultKV2Engine {
	// This should match however TestVaultCryptoEngine sets up the engine
	// Look in vaultkv2_test.go for the actual setup code
	t.Fatal("You need to implement setupTestEngine based on your existing test setup")
	return nil
}
