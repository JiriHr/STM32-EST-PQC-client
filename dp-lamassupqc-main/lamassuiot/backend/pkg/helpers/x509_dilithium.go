package helpers

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// Dilithium OID definitions based on NIST PQC standards
// These OIDs are from the NIST Post-Quantum Cryptography standardization
var (
	// OID for Dilithium2 signature algorithm
	// Format: 1.3.6.1.4.1.2.267.7.4.4
	OIDDilithium2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 4, 4}

	// OID for Dilithium3 signature algorithm
	// Format: 1.3.6.1.4.1.2.267.7.6.5
	OIDDilithium3 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 6, 5}

	// OID for Dilithium5 signature algorithm
	// Format: 1.3.6.1.4.1.2.267.7.8.7
	OIDDilithium5 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 7}

	// OIDs for ML-DSA signature algorithms from FIPS 204 / NIST CSOR
	OIDMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OIDMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// DilithiumSignatureAlgorithm represents a Dilithium signature algorithm
type DilithiumSignatureAlgorithm int

const (
	Dilithium2 DilithiumSignatureAlgorithm = iota
	Dilithium3
	Dilithium5
	UnknownDilithium
)

// PQCPublicKey keeps the raw public key bytes together with the exact PQC
// algorithm. This is needed because Dilithium and ML-DSA variants share public
// key sizes, so raw bytes alone cannot identify the algorithm family.
type PQCPublicKey struct {
	Algorithm string
	Bytes     []byte
}

func NewPQCPublicKey(algorithm string, publicKeyBytes []byte) PQCPublicKey {
	return PQCPublicKey{
		Algorithm: algorithm,
		Bytes:     append([]byte(nil), publicKeyBytes...),
	}
}

// GetDilithiumOID returns the OID for a given Dilithium algorithm
func GetDilithiumOID(algorithm string) (asn1.ObjectIdentifier, error) {
	switch algorithm {
	case "DILITHIUM_2", "DILITHIUM2":
		return OIDDilithium2, nil
	case "DILITHIUM_3", "DILITHIUM3":
		return OIDDilithium3, nil
	case "DILITHIUM_5", "DILITHIUM5":
		return OIDDilithium5, nil
	default:
		return nil, fmt.Errorf("unknown dilithium algorithm: %s", algorithm)
	}
}

func GetMLDSAOID(algorithm string) (asn1.ObjectIdentifier, error) {
	switch algorithm {
	case "ML_DSA_44", "MLDSA44", "ML-DSA-44":
		return OIDMLDSA44, nil
	case "ML_DSA_65", "MLDSA65", "ML-DSA-65":
		return OIDMLDSA65, nil
	case "ML_DSA_87", "MLDSA87", "ML-DSA-87":
		return OIDMLDSA87, nil
	default:
		return nil, fmt.Errorf("unknown ML-DSA algorithm: %s", algorithm)
	}
}

func GetPQCAlgorithmOID(algorithm string) (asn1.ObjectIdentifier, error) {
	if oid, err := GetDilithiumOID(algorithm); err == nil {
		return oid, nil
	}
	return GetMLDSAOID(algorithm)
}

// GetDilithiumAlgorithmFromOID returns the algorithm name from an OID
func GetDilithiumAlgorithmFromOID(oid asn1.ObjectIdentifier) (string, error) {
	switch {
	case oid.Equal(OIDDilithium2):
		return "DILITHIUM_2", nil
	case oid.Equal(OIDDilithium3):
		return "DILITHIUM_3", nil
	case oid.Equal(OIDDilithium5):
		return "DILITHIUM_5", nil
	default:
		return "", fmt.Errorf("unknown dilithium OID: %v", oid)
	}
}

func GetMLDSAAlgorithmFromOID(oid asn1.ObjectIdentifier) (string, error) {
	switch {
	case oid.Equal(OIDMLDSA44):
		return "ML_DSA_44", nil
	case oid.Equal(OIDMLDSA65):
		return "ML_DSA_65", nil
	case oid.Equal(OIDMLDSA87):
		return "ML_DSA_87", nil
	default:
		return "", fmt.Errorf("unknown ML-DSA OID: %v", oid)
	}
}

func GetPQCAlgorithmFromOID(oid asn1.ObjectIdentifier) (string, error) {
	if algorithm, err := GetDilithiumAlgorithmFromOID(oid); err == nil {
		return algorithm, nil
	}
	return GetMLDSAAlgorithmFromOID(oid)
}

// IsDilithiumAlgorithm checks if the given algorithm string is a Dilithium algorithm
func IsDilithiumAlgorithm(algorithm string) bool {
	switch algorithm {
	case "DILITHIUM_2", "DILITHIUM2", "DILITHIUM_3", "DILITHIUM3", "DILITHIUM_5", "DILITHIUM5":
		return true
	default:
		return false
	}
}

func IsMLDSAAlgorithm(algorithm string) bool {
	switch algorithm {
	case "ML_DSA_44", "MLDSA44", "ML-DSA-44", "ML_DSA_65", "MLDSA65", "ML-DSA-65", "ML_DSA_87", "MLDSA87", "ML-DSA-87":
		return true
	default:
		return false
	}
}

func IsPQCAlgorithm(algorithm string) bool {
	return IsDilithiumAlgorithm(algorithm) || IsMLDSAAlgorithm(algorithm)
}

// CreateDilithiumSignatureAlgorithm creates a pkix.AlgorithmIdentifier for Dilithium
func CreateDilithiumSignatureAlgorithm(algorithm string) (pkix.AlgorithmIdentifier, error) {
	oid, err := GetDilithiumOID(algorithm)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}

	// Dilithium signatures don't use parameters (NULL parameters)
	return pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.NullRawValue,
	}, nil
}

func CreateMLDSASignatureAlgorithm(algorithm string) (pkix.AlgorithmIdentifier, error) {
	oid, err := GetMLDSAOID(algorithm)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}

	return pkix.AlgorithmIdentifier{
		Algorithm: oid,
	}, nil
}

func CreatePQCSignatureAlgorithm(algorithm string) (pkix.AlgorithmIdentifier, error) {
	if IsMLDSAAlgorithm(algorithm) {
		return CreateMLDSASignatureAlgorithm(algorithm)
	}

	oid, err := GetPQCAlgorithmOID(algorithm)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}

	return pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.NullRawValue,
	}, nil
}

// DilithiumPublicKeyInfo represents the structure for encoding Dilithium public keys
type DilithiumPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// EncodeDilithiumPublicKey encodes a Dilithium public key into PKIX format
func EncodeDilithiumPublicKey(algorithm string, publicKeyBytes []byte) ([]byte, error) {
	algorithmIdentifier, err := CreatePQCSignatureAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	pubKeyInfo := DilithiumPublicKeyInfo{
		Algorithm: algorithmIdentifier,
		PublicKey: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: len(publicKeyBytes) * 8,
		},
	}

	return asn1.Marshal(pubKeyInfo)
}

func EncodeMLDSAPublicKey(algorithm string, publicKeyBytes []byte) ([]byte, error) {
	return EncodeDilithiumPublicKey(algorithm, publicKeyBytes)
}

// GetDilithiumPublicKeySize returns the expected public key size for each Dilithium variant
func GetDilithiumPublicKeySize(algorithm string) (int, error) {
	switch algorithm {
	case "DILITHIUM_2", "DILITHIUM2":
		return 1312, nil // Dilithium2 public key size
	case "DILITHIUM_3", "DILITHIUM3":
		return 1952, nil // Dilithium3 public key size
	case "DILITHIUM_5", "DILITHIUM5":
		return 2592, nil // Dilithium5 public key size
	default:
		return 0, fmt.Errorf("unknown dilithium algorithm: %s", algorithm)
	}
}

func GetMLDSAPublicKeySize(algorithm string) (int, error) {
	switch algorithm {
	case "ML_DSA_44", "MLDSA44", "ML-DSA-44":
		return 1312, nil
	case "ML_DSA_65", "MLDSA65", "ML-DSA-65":
		return 1952, nil
	case "ML_DSA_87", "MLDSA87", "ML-DSA-87":
		return 2592, nil
	default:
		return 0, fmt.Errorf("unknown ML-DSA algorithm: %s", algorithm)
	}
}

// GetDilithiumSignatureSize returns the expected signature size for each Dilithium variant
func GetDilithiumSignatureSize(algorithm string) (int, error) {
	switch algorithm {
	case "DILITHIUM_2", "DILITHIUM2":
		return 2420, nil // Dilithium2 signature size
	case "DILITHIUM_3", "DILITHIUM3":
		return 3293, nil // Dilithium3 signature size
	case "DILITHIUM_5", "DILITHIUM5":
		return 4595, nil // Dilithium5 signature size
	default:
		return 0, fmt.Errorf("unknown dilithium algorithm: %s", algorithm)
	}
}

func GetMLDSASignatureSize(algorithm string) (int, error) {
	switch algorithm {
	case "ML_DSA_44", "MLDSA44", "ML-DSA-44":
		return 2420, nil
	case "ML_DSA_65", "MLDSA65", "ML-DSA-65":
		return 3309, nil
	case "ML_DSA_87", "MLDSA87", "ML-DSA-87":
		return 4627, nil
	default:
		return 0, fmt.Errorf("unknown ML-DSA algorithm: %s", algorithm)
	}
}
