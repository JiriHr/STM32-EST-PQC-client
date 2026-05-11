package models

import (
	"crypto/x509"
	"encoding/json"
)

type KeyStrength string

const (
	KeyStrengthHigh   KeyStrength = "HIGH"
	KeyStrengthMedium KeyStrength = "MEDIUM"
	KeyStrengthLow    KeyStrength = "LOW"
)

type KeyType x509.PublicKeyAlgorithm

const (
	KeyTypeDilithium2 KeyType = 100 // Custom value for PQC
	KeyTypeDilithium3 KeyType = 101
	KeyTypeDilithium5 KeyType = 102
	KeyTypeMLDSA44    KeyType = 103
	KeyTypeMLDSA65    KeyType = 104
	KeyTypeMLDSA87    KeyType = 105
)

type KeyMetadata struct {
	KeyID string  `json:"key_id"`
	Type  KeyType `json:"type" gorm:"serializer:text" enums:"RSA,ECDSA,Ed25519,DILITHIUM2,DILITHIUM3,DILITHIUM5,ML-DSA-44,ML-DSA-65,ML-DSA-87"`
	Bits  int     `json:"bits"`
}

type KeyStrengthMetadata struct {
	Type     KeyType     `json:"type" gorm:"serializer:text" enums:"RSA,ECDSA,Ed25519,DILITHIUM2,DILITHIUM3,DILITHIUM5,ML-DSA-44,ML-DSA-65,ML-DSA-87"`
	Bits     int         `json:"bits"`
	Strength KeyStrength `json:"strength"`
}

//---------------------------------------

func (kt KeyType) IsPQC() bool {
	return kt == KeyTypeDilithium2 || kt == KeyTypeDilithium3 || kt == KeyTypeDilithium5 ||
		kt == KeyTypeMLDSA44 || kt == KeyTypeMLDSA65 || kt == KeyTypeMLDSA87
}

func (kt KeyType) GetDilithiumMode() string {
	switch kt {
	case KeyTypeDilithium2:
		return "2"
	case KeyTypeDilithium3:
		return "3"
	case KeyTypeDilithium5:
		return "5"
	default:
		return ""
	}
}

func (kt KeyType) GetMLDSASecurityVersion() string {
	switch kt {
	case KeyTypeMLDSA44:
		return "44"
	case KeyTypeMLDSA65:
		return "65"
	case KeyTypeMLDSA87:
		return "87"
	default:
		return ""
	}
}

func (kt KeyType) String() string {
	// Handle PQC types first
	switch kt {
	case KeyTypeDilithium2:
		return "DILITHIUM2"
	case KeyTypeDilithium3:
		return "DILITHIUM3"
	case KeyTypeDilithium5:
		return "DILITHIUM5"
	case KeyTypeMLDSA44:
		return "ML-DSA-44"
	case KeyTypeMLDSA65:
		return "ML-DSA-65"
	case KeyTypeMLDSA87:
		return "ML-DSA-87"
	default:
		// Fall back to standard x509 types
		publicKeyAlg := x509.PublicKeyAlgorithm(kt)
		return publicKeyAlg.String()
	}
}

func (kt KeyType) MarshalText() ([]byte, error) {
	return []byte(kt.String()), nil
}

func (kt *KeyType) UnmarshalText(text []byte) error {
	k, err := ParseKeyType(string(text))
	if err != nil {
		return err
	}

	*kt = *k
	return nil
}

func (kt KeyType) MarshalJSON() ([]byte, error) {
	str := kt.String()
	return json.Marshal(str)
}

func (kt *KeyType) UnmarshalJSON(data []byte) error {
	var t string
	err := json.Unmarshal(data, &t)
	if err != nil {
		return err
	}

	nkt, err := ParseKeyType(t)
	if err != nil {
		return err
	}

	*kt = *nkt
	return nil
}

func ParseKeyType(s string) (*KeyType, error) {
	var nkt KeyType

	switch s {
	case "UNKNOWN":
		nkt = KeyType(x509.UnknownPublicKeyAlgorithm)
	case "RSA":
		nkt = KeyType(x509.RSA)
	case "DSA":
		nkt = KeyType(x509.DSA)
	case "ECDSA":
		nkt = KeyType(x509.ECDSA)
	case "Ed25519":
		nkt = KeyType(x509.Ed25519)
	//added Dilithium
	case "DILITHIUM2":
		nkt = KeyTypeDilithium2
	case "DILITHIUM3":
		nkt = KeyTypeDilithium3
	case "DILITHIUM5":
		nkt = KeyTypeDilithium5
	case "ML_DSA_44", "MLDSA44", "ML-DSA-44":
		nkt = KeyTypeMLDSA44
	case "ML_DSA_65", "MLDSA65", "ML-DSA-65":
		nkt = KeyTypeMLDSA65
	case "ML_DSA_87", "MLDSA87", "ML-DSA-87":
		nkt = KeyTypeMLDSA87
	default:
		nkt = KeyType(x509.UnknownPublicKeyAlgorithm)
	}

	return &nkt, nil
}
