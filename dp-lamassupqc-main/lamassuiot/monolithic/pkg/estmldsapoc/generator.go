package estmldsapoc

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers"
	bconfig "github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/pqc"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/storage/sqlite"
)

type Variant struct {
	SecurityVersion int
	KeyType         models.KeyType
	PQCAlgorithm    pqc.Algorithm
	X509Algorithm   string
	Label           string
	Slug            string
}

var (
	MLDSA44 = Variant{
		SecurityVersion: 44,
		KeyType:         models.KeyTypeMLDSA44,
		PQCAlgorithm:    pqc.MLDSA44,
		X509Algorithm:   "ML_DSA_44",
		Label:           "ML-DSA-44",
		Slug:            "mldsa44",
	}
	MLDSA65 = Variant{
		SecurityVersion: 65,
		KeyType:         models.KeyTypeMLDSA65,
		PQCAlgorithm:    pqc.MLDSA65,
		X509Algorithm:   "ML_DSA_65",
		Label:           "ML-DSA-65",
		Slug:            "mldsa65",
	}
	MLDSA87 = Variant{
		SecurityVersion: 87,
		KeyType:         models.KeyTypeMLDSA87,
		PQCAlgorithm:    pqc.MLDSA87,
		X509Algorithm:   "ML_DSA_87",
		Label:           "ML-DSA-87",
		Slug:            "mldsa87",
	}
)

func Run(ctx context.Context, variant Variant) error {
	outPath := fmt.Sprintf("/tmp/lamassu-est-%s-cert.pem", variant.Slug)
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("lamassu-est-%s-*", variant.Slug))
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	sqlite.Register()
	storageConfig := cconfig.PluggableStorageEngine{
		LogLevel: cconfig.Info,
		Provider: cconfig.SQLite,
		Config: map[string]interface{}{
			"path": filepath.Join(tmpDir, "lamassu.sqlite"),
		},
	}

	apiInfo := models.APIServiceInfo{Version: "poc", BuildSHA: "-", BuildTime: "-"}
	eventBus := cconfig.EventBusEngine{Enabled: false}
	cryptoEngines := bconfig.CryptoEngines{
		LogLevel:          cconfig.Info,
		DefaultEngine:     "filesystem-1",
		MigrateKeysFormat: false,
		CryptoEngines: []cconfig.CryptoEngineConfig{{
			ID:       "filesystem-1",
			Metadata: map[string]interface{}{},
			Type:     cconfig.FilesystemProvider,
			Config: map[string]interface{}{
				"storage_directory": filepath.Join(tmpDir, "keys"),
			},
		}},
	}

	kmsSvc, kmsPort, err := assemblers.AssembleKMSServiceWithHTTPServer(bconfig.KMSConfig{
		Logs:               cconfig.Logging{Level: cconfig.Info},
		Server:             cconfig.HttpServer{LogLevel: cconfig.Info, ListenAddress: "127.0.0.1", Port: 0, Protocol: cconfig.HTTP},
		CryptoEngineConfig: cryptoEngines,
		PublisherEventBus:  eventBus,
		Storage:            storageConfig,
	}, apiInfo)
	if err != nil {
		return fmt.Errorf("assemble KMS: %w", err)
	}
	_ = kmsPort

	caSvc, _, caPort, err := assemblers.AssembleCAServiceWithHTTPServer(bconfig.CAConfig{
		Logs:              cconfig.Logging{Level: cconfig.Info},
		Server:            cconfig.HttpServer{LogLevel: cconfig.Info, ListenAddress: "127.0.0.1", Port: 0, Protocol: cconfig.HTTP},
		PublisherEventBus: eventBus,
		Storage:           storageConfig,
	}, *kmsSvc, apiInfo)
	if err != nil {
		return fmt.Errorf("assemble CA: %w", err)
	}
	_ = caPort

	devSvc, _, err := assemblers.AssembleDeviceManagerServiceWithHTTPServer(bconfig.DeviceManagerConfig{
		Logs:              cconfig.Logging{Level: cconfig.Info},
		Server:            cconfig.HttpServer{LogLevel: cconfig.Info, ListenAddress: "127.0.0.1", Port: 0, Protocol: cconfig.HTTP},
		PublisherEventBus: eventBus,
		Storage:           storageConfig,
	}, *caSvc, apiInfo)
	if err != nil {
		return fmt.Errorf("assemble device manager: %w", err)
	}

	serverKey, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		return err
	}
	serverKeyPEM, err := chelpers.PrivateKeyToPEM(serverKey)
	if err != nil {
		return err
	}
	serverCert, err := chelpers.GenerateSelfSignedCertificate(serverKey, fmt.Sprintf("lamassu-est-%s.local", variant.Slug))
	if err != nil {
		return err
	}
	serverCertPath := filepath.Join(tmpDir, "est-server.crt")
	serverKeyPath := filepath.Join(tmpDir, "est-server.key")
	if err := os.WriteFile(serverCertPath, []byte(chelpers.CertificateToPEM(serverCert)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(serverKeyPath, []byte(serverKeyPEM), 0o600); err != nil {
		return err
	}

	dmsSvc, dmsPort, err := assemblers.AssembleDMSManagerServiceWithHTTPServer(bconfig.DMSconfig{
		Logs: cconfig.Logging{Level: cconfig.Info},
		Server: cconfig.HttpServer{
			LogLevel:      cconfig.Info,
			ListenAddress: "127.0.0.1",
			Port:          0,
			Protocol:      cconfig.HTTPS,
			CertFile:      serverCertPath,
			KeyFile:       serverKeyPath,
			Authentication: cconfig.HttpServerAuthentication{
				MutualTLS: cconfig.HttpServerMutualTLSAuthentication{
					Enabled:           true,
					ValidationMode:    cconfig.Request,
					CACertificateFile: serverCertPath,
				},
			},
		},
		PublisherEventBus:         eventBus,
		Storage:                   storageConfig,
		DownstreamCertificateFile: serverCertPath,
	}, *caSvc, *devSvc, apiInfo)
	if err != nil {
		return fmt.Errorf("assemble DMS: %w", err)
	}

	profile, err := (*caSvc).CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:        fmt.Sprintf("%s-est-device-profile", variant.Slug),
			Description: fmt.Sprintf("POC profile for EST-issued %s device certificates", variant.Label),
			Validity:    models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
			CryptoEnforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:                      true,
				AllowMLDSAKeys:               true,
				AllowedMLDSASecurityVersions: []int{variant.SecurityVersion},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create issuance profile: %w", err)
	}

	ca, err := (*caSvc).CreateCA(ctx, services.CreateCAInput{
		ID:           fmt.Sprintf("%s-est-ca", variant.Slug),
		KeyMetadata:  models.KeyMetadata{Type: variant.KeyType, Bits: 0},
		Subject:      models.Subject{CommonName: fmt.Sprintf("%s EST CA", variant.Label)},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
		Metadata:     map[string]any{"poc": true, "algorithm": variant.Label},
	})
	if err != nil {
		return fmt.Errorf("create CA: %w", err)
	}

	dmsID := uuid.NewString()
	deviceID := fmt.Sprintf("%s-est-device-001", variant.Slug)
	_, err = (*dmsSvc).CreateDMS(ctx, services.CreateDMSInput{
		ID:       dmsID,
		Name:     fmt.Sprintf("%s EST POC", variant.Label),
		Metadata: map[string]any{"poc": true, "algorithm": variant.Label},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
					AuthMode: models.ESTAuthMode(identityextractors.IdentityExtractorNoAuth),
				},
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "Cpu",
					IconColor: "#355C7D",
					Metadata:  map[string]any{"poc": true, "algorithm": variant.Label},
					Tags:      []string{"pqc", "est", variant.Slug},
				},
				EnrollmentCA:                ca.ID,
				RegistrationMode:            models.JITP,
				EnableReplaceableEnrollment: true,
				VerifyCSRSignature:          true,
			},
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				AdditionalValidationCAs:     []string{},
				ReEnrollmentDelta:           models.TimeDuration(time.Minute),
				EnableExpiredRenewal:        true,
				PreventiveReEnrollmentDelta: models.TimeDuration(10 * time.Minute),
				CriticalReEnrollmentDelta:   models.TimeDuration(5 * time.Minute),
			},
			CADistributionSettings: models.CADistributionSettings{
				IncludeEnrollmentCA: true,
			},
			IssuanceProfileID: profile.ID,
		},
	})
	if err != nil {
		return fmt.Errorf("create DMS: %w", err)
	}

	material, err := helpers.CreateMLDSACertificateRequest(models.Subject{CommonName: deviceID}, variant.PQCAlgorithm)
	if err != nil {
		return fmt.Errorf("create %s CSR: %w", variant.Label, err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
			},
		},
	}
	baseURL := fmt.Sprintf("https://127.0.0.1:%d", dmsPort)
	enrolledCert, err := helpers.ESTSimpleEnrollPEM(ctx, httpClient, baseURL, dmsID, material.CSR)
	if err != nil {
		return fmt.Errorf("EST simpleenroll: %w", err)
	}

	algorithm, _, err := helpers.ExtractPQCPublicKeyFromSPKI(enrolledCert.RawSubjectPublicKeyInfo)
	if err != nil {
		return fmt.Errorf("extract PQC public key: %w", err)
	}
	if algorithm != variant.X509Algorithm {
		return fmt.Errorf("expected %s public key, got %s", variant.X509Algorithm, algorithm)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: enrolledCert.Raw})
	if err := os.WriteFile(outPath, certPEM, 0o600); err != nil {
		return err
	}

	fmt.Printf("wrote %s\n", outPath)
	fmt.Printf("subject=%s\n", enrolledCert.Subject.String())
	fmt.Printf("issuer=%s\n", enrolledCert.Issuer.String())
	fmt.Printf("serial=%s\n", enrolledCert.SerialNumber.String())
	fmt.Printf("public_key_algorithm=%s\n", algorithm)

	return nil
}
