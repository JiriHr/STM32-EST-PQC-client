package dmsmanager

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/pqc"
)

func TestGenerateESTMLDSA87Certificate(t *testing.T) {
	ctx := context.Background()
	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	profile, err := testServers.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
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
		t.Fatalf("could not create ML-DSA-87 issuance profile: %s", err)
	}

	ca, err := testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
		ID:           "mldsa87-est-ca",
		KeyMetadata:  models.KeyMetadata{Type: models.KeyTypeMLDSA87, Bits: 0},
		Subject:      models.Subject{CommonName: "ML-DSA-87 EST CA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
		Metadata:     map[string]any{"poc": true, "algorithm": "ML-DSA-87"},
	})
	if err != nil {
		t.Fatalf("could not create ML-DSA-87 CA: %s", err)
	}

	dmsID := uuid.NewString()
	deviceID := "mldsa87-est-device-001"
	_, err = dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
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
		t.Fatalf("could not create ML-DSA-87 DMS: %s", err)
	}

	material, err := helpers.CreateMLDSACertificateRequest(models.Subject{CommonName: deviceID}, pqc.MLDSA87)
	if err != nil {
		t.Fatalf("could not create ML-DSA-87 CSR: %s", err)
	}

	baseURL := fmt.Sprintf("https://127.0.0.1:%d", dmsMgr.Port)
	enrolledCert, err := helpers.ESTSimpleEnrollPEM(ctx, estPOCTestHTTPClient(), baseURL, dmsID, material.CSR)
	if err != nil {
		t.Fatalf("could not enroll ML-DSA-87 CSR over EST: %s", err)
	}

	algorithm, _, err := helpers.ExtractPQCPublicKeyFromSPKI(enrolledCert.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatalf("enrolled certificate does not contain a PQC public key: %s", err)
	}
	if algorithm != "ML_DSA_87" {
		t.Fatalf("expected ML_DSA_87 public key, got %s", algorithm)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: enrolledCert.Raw})
	outPath := "/tmp/lamassu-est-mldsa87-cert.pem"
	if err := os.WriteFile(outPath, certPEM, 0o600); err != nil {
		t.Fatalf("could not write ML-DSA-87 certificate: %s", err)
	}

	t.Logf("wrote ML-DSA-87 EST certificate to %s", outPath)
	t.Logf("serial=%s subject=%s issuer=%s", enrolledCert.SerialNumber, enrolledCert.Subject.String(), enrolledCert.Issuer.String())
}
