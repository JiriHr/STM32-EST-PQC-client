package helpers

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestMLDSAAlgorithmIdentifierOmitsParameters(t *testing.T) {
	for _, tc := range []struct {
		name      string
		algorithm string
		oid       asn1.ObjectIdentifier
	}{
		{name: "ML-DSA-44", algorithm: "ML_DSA_44", oid: OIDMLDSA44},
		{name: "ML-DSA-65", algorithm: "ML_DSA_65", oid: OIDMLDSA65},
		{name: "ML-DSA-87", algorithm: "ML_DSA_87", oid: OIDMLDSA87},
	} {
		t.Run(tc.name, func(t *testing.T) {
			algorithmIdentifier, err := CreatePQCSignatureAlgorithm(tc.algorithm)
			if err != nil {
				t.Fatalf("CreatePQCSignatureAlgorithm failed: %s", err)
			}

			if len(algorithmIdentifier.Parameters.FullBytes) != 0 {
				t.Fatalf("expected ML-DSA parameters to be absent, got %x", algorithmIdentifier.Parameters.FullBytes)
			}

			der, err := asn1.Marshal(algorithmIdentifier)
			if err != nil {
				t.Fatalf("could not marshal ML-DSA AlgorithmIdentifier: %s", err)
			}

			var parsed struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(der, &parsed); err != nil {
				t.Fatalf("could not parse ML-DSA AlgorithmIdentifier: %s", err)
			}

			if !parsed.Algorithm.Equal(tc.oid) {
				t.Fatalf("expected %s OID, got %v", tc.name, parsed.Algorithm)
			}
			if len(parsed.Parameters.FullBytes) != 0 {
				t.Fatalf("expected encoded ML-DSA parameters to be absent, got %x", parsed.Parameters.FullBytes)
			}
		})
	}
}

func TestEncodeMLDSAPublicKeyOmitsAlgorithmParameters(t *testing.T) {
	for _, tc := range mldsaPublicKeyTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			publicKey := bytes.Repeat([]byte{0x42}, tc.publicKeySize)

			der, err := EncodeMLDSAPublicKey(tc.algorithm, publicKey)
			if err != nil {
				t.Fatalf("EncodeMLDSAPublicKey failed: %s", err)
			}

			var spki customSubjectPublicKeyInfo
			if _, err := asn1.Unmarshal(der, &spki); err != nil {
				t.Fatalf("could not parse ML-DSA SubjectPublicKeyInfo: %s", err)
			}

			if !spki.Algorithm.Algorithm.Equal(tc.oid) {
				t.Fatalf("expected %s OID, got %v", tc.name, spki.Algorithm.Algorithm)
			}
			if len(spki.Algorithm.Parameters.FullBytes) != 0 {
				t.Fatalf("expected ML-DSA SPKI parameters to be absent, got %x", spki.Algorithm.Parameters.FullBytes)
			}
			if !bytes.Equal(spki.PublicKey.Bytes, publicKey) {
				t.Fatal("decoded public key bytes do not match input")
			}
		})
	}
}

func TestMarshalMLDSASubjectPublicKeyInfoOmitsAlgorithmParameters(t *testing.T) {
	for _, tc := range mldsaPublicKeyTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			publicKey := bytes.Repeat([]byte{0x24}, tc.publicKeySize)

			spki, rawPublicKey, err := marshalSubjectPublicKeyInfo(NewPQCPublicKey(tc.algorithm, publicKey), tc.algorithm)
			if err != nil {
				t.Fatalf("marshalSubjectPublicKeyInfo failed: %s", err)
			}

			if !spki.Algorithm.Algorithm.Equal(tc.oid) {
				t.Fatalf("expected %s OID, got %v", tc.name, spki.Algorithm.Algorithm)
			}
			if len(spki.Algorithm.Parameters.FullBytes) != 0 {
				t.Fatalf("expected marshaled ML-DSA SPKI parameters to be absent, got %x", spki.Algorithm.Parameters.FullBytes)
			}
			if !bytes.Equal(rawPublicKey, publicKey) {
				t.Fatal("raw public key bytes do not match input")
			}
		})
	}
}

type mldsaPublicKeyTestCase struct {
	name          string
	algorithm     string
	oid           asn1.ObjectIdentifier
	publicKeySize int
}

func mldsaPublicKeyTestCases() []mldsaPublicKeyTestCase {
	return []mldsaPublicKeyTestCase{
		{name: "ML-DSA-44", algorithm: "ML_DSA_44", oid: OIDMLDSA44, publicKeySize: 1312},
		{name: "ML-DSA-65", algorithm: "ML_DSA_65", oid: OIDMLDSA65, publicKeySize: 1952},
		{name: "ML-DSA-87", algorithm: "ML_DSA_87", oid: OIDMLDSA87, publicKeySize: 2592},
	}
}
