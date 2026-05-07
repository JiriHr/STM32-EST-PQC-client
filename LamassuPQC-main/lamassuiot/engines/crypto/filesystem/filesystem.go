package filesystem

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/pqc"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

type FilesystemCryptoEngine struct {
	softCryptoEngine *software.SoftwareCryptoEngine
	pqcProvider      pqc.Provider
	config           models.CryptoEngineInfo
	storageDirectory string
	logger           *logrus.Entry
}

type dilithiumKeyFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Algorithm  string `json:"algorithm"`
	KeyType    string `json:"key_type"`
	Mode       string `json:"mode"`
}

func NewFilesystemPEMEngine(logger *logrus.Entry, conf config.CryptoEngineConfigAdapter[FilesystemEngineConfig]) (cryptoengines.CryptoEngine, error) {
	lGo := logger.WithField("subsystem-provider", "GoSoft")

	defaultMeta := map[string]interface{}{
		"lamassu.io/cryptoengine.golang.storage-path": conf,
	}

	err := checkAndCreateStorageDir(lGo, conf.Config.StorageDirectory)
	if err != nil {
		return nil, err
	}

	meta := helpers.MergeMaps(&defaultMeta, &conf.Metadata)
	return &FilesystemCryptoEngine{
		logger:           lGo,
		softCryptoEngine: software.NewSoftwareCryptoEngine(lGo),
		pqcProvider:      pqc.NewDilithiumProvider(),
		storageDirectory: conf.Config.StorageDirectory,
		config: models.CryptoEngineInfo{
			Type:          models.Golang,
			SecurityLevel: models.SL0,
			Provider:      "Golang",
			Name:          runtime.Version(),
			Metadata:      *meta,
			SupportedKeyTypes: []models.SupportedKeyTypeInfo{
				{
					Type: models.KeyType(x509.RSA),
					Sizes: []int{
						1024,
						2048,
						3072,
						4096,
						7680,
						15360,
					},
				},
				{
					Type: models.KeyType(x509.ECDSA),
					Sizes: []int{
						224,
						256,
						384,
						521,
					},
				},
				{
					Type:  models.KeyTypeDilithium2,
					Sizes: []int{0},
				},
				{
					Type:  models.KeyTypeDilithium3,
					Sizes: []int{0},
				},
				{
					Type:  models.KeyTypeDilithium5,
					Sizes: []int{0},
				},
				{
					Type:  models.KeyTypeMLDSA44,
					Sizes: []int{0},
				},
				{
					Type:  models.KeyTypeMLDSA65,
					Sizes: []int{0},
				},
				{
					Type:  models.KeyTypeMLDSA87,
					Sizes: []int{0},
				},
			},
		},
	}, nil
}

func (engine *FilesystemCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return engine.config
}

func (engine *FilesystemCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	engine.logger.Debugf("reading %s Key", keyID)
	file := filepath.Join(engine.storageDirectory, keyID)

	pemBytes, err := os.ReadFile(file)
	if err != nil {
		engine.logger.Errorf("Could not read %s Key: %s", keyID, err)
		return nil, err
	}

	return engine.softCryptoEngine.ParsePrivateKey(pemBytes)
}

func (engine *FilesystemCryptoEngine) ListPrivateKeyIDs() ([]string, error) {
	// Update KeyIDs in folder and remove old naming
	entries, err := os.ReadDir(engine.storageDirectory)
	if err != nil {
		return nil, err
	}

	var keyIDs []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		keyIDs = append(keyIDs, entry.Name())
	}

	return keyIDs, nil
}

func (engine *FilesystemCryptoEngine) RenameKey(oldID, newID string) error {
	engine.logger.Debugf("renaming key %s to %s", oldID, newID)
	err := os.Rename(filepath.Join(engine.storageDirectory, oldID), filepath.Join(engine.storageDirectory, newID))
	if err != nil {
		engine.logger.Errorf("could not rename key %s to %s: %s", oldID, newID, err)
		return err
	}

	engine.logger.Debugf("key %s successfully renamed to %s", oldID, newID)
	return nil
}

func (engine *FilesystemCryptoEngine) CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating RSA private key")

	_, key, err := engine.softCryptoEngine.CreateRSAPrivateKey(ctx, keySize)
	if err != nil {
		engine.logger.Errorf("could not create RSA private key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("RSA key successfully generated")
	return engine.importKey(key)
}

func (engine *FilesystemCryptoEngine) CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating ECDSA private key")

	_, key, err := engine.softCryptoEngine.CreateECDSAPrivateKey(ctx, curve)
	if err != nil {
		engine.logger.Errorf("could not create ECDSA private key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("ECDSA key successfully generated")
	return engine.importKey(key)
}

func (engine *FilesystemCryptoEngine) DeleteKey(keyID string) error {
	return os.Remove(engine.storageDirectory + "/" + keyID)
}

func (engine *FilesystemCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error) {
	engine.logger.Debugf("importing RSA private key")

	keyID, signer, err := engine.importKey(key)
	if err != nil {
		engine.logger.Errorf("could not import RSA key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("RSA key successfully imported")
	return keyID, signer, nil
}

func (engine *FilesystemCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	engine.logger.Debugf("importing ECDSA private key")

	keyID, signer, err := engine.importKey(key)
	if err != nil {
		engine.logger.Errorf("could not import ECDSA key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("ECDSA key successfully imported")
	return keyID, signer, nil
}

func (engine *FilesystemCryptoEngine) importKey(key interface{}) (string, crypto.Signer, error) {
	pubKey := key.(crypto.Signer).Public()

	keyID, err := engine.softCryptoEngine.EncodePKIXPublicKeyDigest(pubKey)
	if err != nil {
		engine.logger.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	b64PemKey, err := engine.softCryptoEngine.MarshalAndEncodePKIXPrivateKey(key)
	if err != nil {
		engine.logger.Errorf("could not marshal and encode private key: %s", err)
		return "", nil, err
	}

	pemKey, err := base64.StdEncoding.DecodeString(b64PemKey)
	if err != nil {
		engine.logger.Errorf("could not decode RSA private key: %s", err)
		return "", nil, err
	}

	file := filepath.Join(engine.storageDirectory, keyID)
	err = os.WriteFile(file, pemKey, 0600)
	if err != nil {
		engine.logger.Errorf("could not store RSA private key: %s", err)
		return "", nil, err
	}

	signer, err := engine.GetPrivateKeyByID(keyID)
	if err != nil {
		engine.logger.Errorf("could not get private key by ID: %s", err)
		return "", nil, err
	}

	return keyID, signer, nil
}

func checkAndCreateStorageDir(logger *logrus.Entry, dir string) error {
	var err error
	if _, err = os.Stat(dir); os.IsNotExist(err) {
		logger.Warnf("storage directory %s does not exist. Will create such directory", dir)
		err = os.MkdirAll(dir, 0750)
		if err != nil {
			logger.Errorf("something went wrong while creating storage path: %s", err)
		}
		return err
	} else if err != nil {
		logger.Errorf("something went wrong while checking storage: %s", err)
		return err
	}

	return nil
}

func (engine *FilesystemCryptoEngine) CreateDilithiumPrivateKey(ctx context.Context, mode string) (string, []byte, error) {
	engine.logger.Debugf("creating Dilithium private key with mode %s", mode)

	algorithm, err := dilithiumAlgorithmFromMode(mode)
	if err != nil {
		return "", nil, err
	}

	keyPair, err := engine.pqcProvider.GenerateKeyPair(algorithm)
	if err != nil {
		engine.logger.Errorf("could not generate Dilithium key pair: %s", err)
		return "", nil, fmt.Errorf("failed to generate Dilithium key: %w", err)
	}

	keyID := dilithiumKeyID(keyPair.PublicKey)
	keyType := "dilithium"
	if algorithm == pqc.MLDSA44 || algorithm == pqc.MLDSA65 || algorithm == pqc.MLDSA87 {
		keyType = "mldsa"
	}

	keyFile := dilithiumKeyFile{
		PrivateKey: base64.StdEncoding.EncodeToString(keyPair.PrivateKey),
		PublicKey:  base64.StdEncoding.EncodeToString(keyPair.PublicKey),
		Algorithm:  string(algorithm),
		KeyType:    keyType,
		Mode:       mode,
	}

	encoded, err := json.Marshal(keyFile)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal Dilithium key file: %w", err)
	}

	file := filepath.Join(engine.storageDirectory, keyID)
	if err := os.WriteFile(file, encoded, 0600); err != nil {
		engine.logger.Errorf("could not store Dilithium private key: %s", err)
		return "", nil, fmt.Errorf("failed to store Dilithium key: %w", err)
	}

	return keyID, keyPair.PublicKey, nil
}

func (engine *FilesystemCryptoEngine) GetDilithiumPrivateKeyByID(keyID string) ([]byte, error) {
	file := filepath.Join(engine.storageDirectory, keyID)
	encoded, err := os.ReadFile(file)
	if err != nil {
		engine.logger.Errorf("could not read Dilithium key %s: %s", keyID, err)
		return nil, fmt.Errorf("failed to read Dilithium key: %w", err)
	}

	var keyFile dilithiumKeyFile
	if err := json.Unmarshal(encoded, &keyFile); err != nil {
		return nil, fmt.Errorf("stored key %s is not a Dilithium key file: %w", keyID, err)
	}

	if keyFile.KeyType != "dilithium" && keyFile.KeyType != "mldsa" {
		return nil, fmt.Errorf("key %s is not a PQC key", keyID)
	}

	privateKey, err := base64.StdEncoding.DecodeString(keyFile.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Dilithium private key: %w", err)
	}

	return privateKey, nil
}

func (engine *FilesystemCryptoEngine) SignDilithium(keyID string, data []byte, mode string) ([]byte, error) {
	privateKey, err := engine.GetDilithiumPrivateKeyByID(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Dilithium private key: %w", err)
	}

	algorithm, err := dilithiumAlgorithmFromMode(mode)
	if err != nil {
		return nil, err
	}

	signature, err := engine.pqcProvider.Sign(data, privateKey, algorithm)
	if err != nil {
		engine.logger.Errorf("could not sign data with Dilithium: %s", err)
		return nil, fmt.Errorf("failed to sign with Dilithium: %w", err)
	}

	return signature, nil
}

func dilithiumAlgorithmFromMode(mode string) (pqc.Algorithm, error) {
	switch mode {
	case "2":
		return pqc.Dilithium2, nil
	case "3":
		return pqc.Dilithium3, nil
	case "5":
		return pqc.Dilithium5, nil
	case "44":
		return pqc.MLDSA44, nil
	case "65":
		return pqc.MLDSA65, nil
	case "87":
		return pqc.MLDSA87, nil
	default:
		return "", fmt.Errorf("unsupported PQC mode: %s", mode)
	}
}

// dilithiumKeyID mirrors the X.509 SubjectKeyIdentifier derivation used for
// Dilithium certificates so CA signer lookup can find the stored private key.
func dilithiumKeyID(publicKey []byte) string {
	digest := sha1.Sum(publicKey)
	return hex.EncodeToString(digest[:])
}
