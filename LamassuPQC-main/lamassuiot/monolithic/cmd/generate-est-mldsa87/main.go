package main

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

func main() {
	ctx := context.Background()
	outPath := "/tmp/lamassu-est-mldsa87-cert.pem"
	tmpDir, err := os.MkdirTemp("", "lamassu-est-mldsa87-*")
	if err != nil {
		panic(err)
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
		panic(fmt.Errorf("assemble KMS: %w", err))
	}
	_ = kmsPort

	caSvc, _, caPort, err := assemblers.AssembleCAServiceWithHTTPServer(bconfig.CAConfig{
		Logs:              cconfig.Logging{Level: cconfig.Info},
		Server:            cconfig.HttpServer{LogLevel: cconfig.Info, ListenAddress: "127.0.0.1", Port: 0, Protocol: cconfig.HTTP},
		PublisherEventBus: eventBus,
		Storage:           storageConfig,
	}, *kmsSvc, apiInfo)
	if err != nil {
		panic(fmt.Errorf("assemble CA: %w", err))
	}
	_ = caPort

	devSvc, _, err := assemblers.AssembleDeviceManagerServiceWithHTTPServer(bconfig.DeviceManagerConfig{
		Logs:              cconfig.Logging{Level: cconfig.Info},
		Server:            cconfig.HttpServer{LogLevel: cconfig.Info, ListenAddress: "127.0.0.1", Port: 0, Protocol: cconfig.HTTP},
		PublisherEventBus: eventBus,
		Storage:           storageConfig,
	}, *caSvc, apiInfo)
	if err != nil {
		panic(fmt.Errorf("assemble device manager: %w", err))
	}

	serverKey, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		panic(err)
	}
	serverKeyPEM, err := chelpers.PrivateKeyToPEM(serverKey)
	if err != nil {
		panic(err)
	}
	serverCert, err := chelpers.GenerateSelfSignedCertificate(serverKey, "lamassu-est-mldsa87.local")
	if err != nil {
		panic(err)
	}
	serverCertPath := filepath.Join(tmpDir, "est-server.crt")
	serverKeyPath := filepath.Join(tmpDir, "est-server.key")
	if err := os.WriteFile(serverCertPath, []byte(chelpers.CertificateToPEM(serverCert)), 0o600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(serverKeyPath, []byte(serverKeyPEM), 0o600); err != nil {
		panic(err)
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
		panic(fmt.Errorf("assemble DMS: %w", err))
	}

	profile, err := (*caSvc).CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:        "mldsa87-est-device-profile",
			Description: "POC profile for EST-issued ML-DSA-87 device certificates",
			Validity:    models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
			CryptoEnforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:                      true,
				AllowMLDSAKeys:               true,
				AllowedMLDSASecurityVersions: []int{87},
			},
		},
	})
	if err != nil {
		panic(fmt.Errorf("create issuance profile: %w", err))
	}

	ca, err := (*caSvc).CreateCA(ctx, services.CreateCAInput{
		ID:           "mldsa87-est-ca",
		KeyMetadata:  models.KeyMetadata{Type: models.KeyTypeMLDSA87, Bits: 0},
		Subject:      models.Subject{CommonName: "ML-DSA-87 EST CA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
		Metadata:     map[string]any{"poc": true, "algorithm": "ML-DSA-87"},
	})
	if err != nil {
		panic(fmt.Errorf("create CA: %w", err))
	}

	dmsID := uuid.NewString()
	deviceID := "mldsa87-est-device-001"
	_, err = (*dmsSvc).CreateDMS(ctx, services.CreateDMSInput{
		ID:       dmsID,
		Name:     "ML-DSA-87 EST POC",
		Metadata: map[string]any{"poc": true, "algorithm": "ML-DSA-87"},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
					AuthMode: models.ESTAuthMode(identityextractors.IdentityExtractorNoAuth),
				},
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "Cpu",
					IconColor: "#355C7D",
					Metadata:  map[string]any{"poc": true, "algorithm": "ML-DSA-87"},
					Tags:      []string{"pqc", "est", "mldsa87"},
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
		panic(fmt.Errorf("create DMS: %w", err))
	}

	material, err := helpers.CreateMLDSACertificateRequest(models.Subject{CommonName: deviceID}, pqc.MLDSA87)
	if err != nil {
		panic(fmt.Errorf("create ML-DSA-87 CSR: %w", err))
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
		panic(fmt.Errorf("EST simpleenroll: %w", err))
	}

	algorithm, _, err := helpers.ExtractPQCPublicKeyFromSPKI(enrolledCert.RawSubjectPublicKeyInfo)
	if err != nil {
		panic(fmt.Errorf("extract PQC public key: %w", err))
	}
	if algorithm != "ML_DSA_87" {
		panic(fmt.Errorf("expected ML_DSA_87 public key, got %s", algorithm))
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: enrolledCert.Raw})
	if err := os.WriteFile(outPath, certPEM, 0o600); err != nil {
		panic(err)
	}

	fmt.Printf("wrote %s\n", outPath)
	fmt.Printf("subject=%s\n", enrolledCert.Subject.String())
	fmt.Printf("issuer=%s\n", enrolledCert.Issuer.String())
	fmt.Printf("serial=%s\n", enrolledCert.SerialNumber.String())
	fmt.Printf("public_key_algorithm=%s\n", algorithm)
}
