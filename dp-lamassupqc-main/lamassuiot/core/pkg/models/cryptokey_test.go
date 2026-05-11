package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyTypePQC(t *testing.T) {
	t.Run("IsPQC", func(t *testing.T) {
		assert.True(t, KeyTypeDilithium2.IsPQC())
		assert.True(t, KeyTypeDilithium3.IsPQC())
		assert.True(t, KeyTypeDilithium5.IsPQC())
		assert.False(t, KeyType(0).IsPQC())
		assert.False(t, KeyType(1).IsPQC()) // RSA
	})

	t.Run("GetDilithiumMode", func(t *testing.T) {
		assert.Equal(t, "2", KeyTypeDilithium2.GetDilithiumMode())
		assert.Equal(t, "3", KeyTypeDilithium3.GetDilithiumMode())
		assert.Equal(t, "5", KeyTypeDilithium5.GetDilithiumMode())
		assert.Equal(t, "", KeyType(0).GetDilithiumMode())
		assert.Equal(t, "", KeyType(1).GetDilithiumMode())
	})

	t.Run("String", func(t *testing.T) {
		assert.Equal(t, "DILITHIUM2", KeyTypeDilithium2.String())
		assert.Equal(t, "DILITHIUM3", KeyTypeDilithium3.String())
		assert.Equal(t, "DILITHIUM5", KeyTypeDilithium5.String())
		assert.Equal(t, "RSA", KeyType(1).String())
		assert.Equal(t, "ECDSA", KeyType(3).String())
	})

	t.Run("ParseKeyType", func(t *testing.T) {
		tests := []struct {
			input    string
			expected KeyType
		}{
			{"DILITHIUM2", KeyTypeDilithium2},
			{"DILITHIUM3", KeyTypeDilithium3},
			{"DILITHIUM5", KeyTypeDilithium5},
			{"RSA", KeyType(1)},
			{"ECDSA", KeyType(3)},
		}

		for _, tt := range tests {
			t.Run(tt.input, func(t *testing.T) {
				kt, err := ParseKeyType(tt.input)
				require.NoError(t, err)
				assert.Equal(t, tt.expected, *kt)
			})
		}
	})

	t.Run("MarshalJSON", func(t *testing.T) {
		tests := []struct {
			keyType  KeyType
			expected string
		}{
			{KeyTypeDilithium3, `"DILITHIUM3"`},
			{KeyType(1), `"RSA"`},
		}

		for _, tt := range tests {
			t.Run(tt.expected, func(t *testing.T) {
				data, err := json.Marshal(tt.keyType)
				require.NoError(t, err)
				assert.Equal(t, tt.expected, string(data))
			})
		}
	})

	t.Run("UnmarshalJSON", func(t *testing.T) {
		var kt KeyType
		err := json.Unmarshal([]byte(`"DILITHIUM3"`), &kt)
		require.NoError(t, err)
		assert.Equal(t, KeyTypeDilithium3, kt)
		assert.Equal(t, "DILITHIUM3", kt.String())
	})

	t.Run("RoundTrip", func(t *testing.T) {
		original := KeyTypeDilithium3

		// Marshal
		data, err := json.Marshal(original)
		require.NoError(t, err)

		// Unmarshal
		var decoded KeyType
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
		assert.Equal(t, "DILITHIUM3", decoded.String())
		assert.True(t, decoded.IsPQC())
		assert.Equal(t, "3", decoded.GetDilithiumMode())
	})
}

func TestKeyMetadata(t *testing.T) {
	t.Run("PQCKeyMetadata", func(t *testing.T) {
		meta := KeyMetadata{
			KeyID: "test-key-id",
			Type:  KeyTypeDilithium3,
			Bits:  0, // PQC keys don't use Bits
		}

		assert.True(t, meta.Type.IsPQC())
		assert.Equal(t, "3", meta.Type.GetDilithiumMode())

		// Marshal to JSON
		data, err := json.Marshal(meta)
		require.NoError(t, err)

		// Unmarshal back
		var decoded KeyMetadata
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, meta.KeyID, decoded.KeyID)
		assert.Equal(t, meta.Type, decoded.Type)
		assert.True(t, decoded.Type.IsPQC())
	})
}
