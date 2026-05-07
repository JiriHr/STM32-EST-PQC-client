package dmsmanager

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type estPQCClientSimulationConfig struct {
	BaseURL     string
	DMSID       string
	DeviceID    string
	TestServers *tests.TestServer
}

// setupESTPQCClientSimulation creates the server-side objects a device needs
// before it can enroll over EST: an issuance profile, a PQC CA, and a DMS with
// NO_AUTH/JITP enabled for this proof of concept.
func setupESTPQCClientSimulation(t *testing.T) estPQCClientSimulationConfig {
	t.Helper()

	ctx := context.Background()
	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	profile, err := testServers.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:        "pqc-device-profile",
			Description: "POC profile for EST-issued Dilithium device certificates",
			Validity:    models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
			CryptoEnforcement: models.IssuanceProfileCryptoEnforcement{
				Enabled:               true,
				AllowDilithiumKeys:    true,
				AllowedDilithiumModes: []int{3},
			},
		},
	})
	if err != nil {
		t.Fatalf("could not create issuance profile: %s", err)
	}

	ca, err := testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
		ID:           "pqc-est-ca",
		KeyMetadata:  models.KeyMetadata{Type: models.KeyTypeDilithium3, Bits: 0},
		Subject:      models.Subject{CommonName: "PQC EST CA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
		Metadata:     map[string]any{"poc": true},
	})
	if err != nil {
		t.Fatalf("could not create PQC CA: %s", err)
	}

	dmsID := uuid.NewString()
	_, err = dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       dmsID,
		Name:     "PQC EST POC",
		Metadata: map[string]any{"poc": true},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
					AuthMode: models.ESTAuthMode(identityextractors.IdentityExtractorNoAuth),
				},
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "Cpu",
					IconColor: "#355C7D",
					Metadata:  map[string]any{"poc": true},
					Tags:      []string{"pqc", "est", "poc"},
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
		t.Fatalf("could not create DMS: %s", err)
	}

	return estPQCClientSimulationConfig{
		BaseURL:     fmt.Sprintf("https://127.0.0.1:%d", dmsMgr.Port),
		DMSID:       dmsID,
		DeviceID:    "pqc-device-001",
		TestServers: testServers,
	}
}
