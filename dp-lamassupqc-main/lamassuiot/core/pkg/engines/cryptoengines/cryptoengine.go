package cryptoengines

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

type CryptoEngine interface {
	GetEngineConfig() models.CryptoEngineInfo

	ListPrivateKeyIDs() ([]string, error)
	GetPrivateKeyByID(keyID string) (crypto.Signer, error)

	CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error)
	CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, crypto.Signer, error)

	ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error)
	ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error)

	DeleteKey(keyID string) error

	RenameKey(oldID, newID string) error

	//Added context for dilithium methods

	CreateDilithiumPrivateKey(ctx context.Context, mode string) (string, []byte, error)
	GetDilithiumPrivateKeyByID(keyID string) ([]byte, error)
	SignDilithium(keyID string, data []byte, mode string) ([]byte, error)
}

type PQCKeyInfo struct {
	KeyID     string
	PublicKey []byte
	Mode      string // "2", "3", "5" for Dilithium or "44", "65", "87" for ML-DSA
}

var cryptoEngineBuilders = make(map[config.CryptoEngineProvider]func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error))

func RegisterCryptoEngine(name config.CryptoEngineProvider, builder func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error)) {
	cryptoEngineBuilders[name] = builder
}

func GetEngineBuilder(name config.CryptoEngineProvider) func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error) {
	return cryptoEngineBuilders[name]
}
