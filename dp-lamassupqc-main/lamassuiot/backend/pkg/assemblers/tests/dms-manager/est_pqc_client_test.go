package dmsmanager

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/pqc"
)

// TestESTClientRequestsDilithiumCertificate simulates the device side of EST:
// generate a Dilithium CSR, POST it to simpleenroll, and verify Lamassu returns
// and stores a PQC certificate for the newly provisioned device.
func TestESTClientRequestsDilithiumCertificate(t *testing.T) {
	ctx := context.Background()
	cfg := setupESTPQCClientSimulation(t)

	material, err := helpers.CreateDilithiumCertificateRequest(models.Subject{CommonName: cfg.DeviceID}, pqc.Dilithium3)
	if err != nil {
		t.Fatalf("could not create Dilithium CSR: %s", err)
	}

	enrolledCert, err := helpers.ESTSimpleEnrollPEM(ctx, estPOCTestHTTPClient(), cfg.BaseURL, cfg.DMSID, material.CSR)
	if err != nil {
		t.Fatalf("could not enroll Dilithium CSR over EST: %s", err)
	}

	if enrolledCert.Subject.CommonName != cfg.DeviceID {
		t.Fatalf("expected enrolled cert CN %q, got %q", cfg.DeviceID, enrolledCert.Subject.CommonName)
	}
	if _, _, err := helpers.ExtractDilithiumPublicKeyFromSPKI(enrolledCert.RawSubjectPublicKeyInfo); err != nil {
		t.Fatalf("enrolled certificate does not contain a Dilithium public key: %s", err)
	}

	device, err := cfg.TestServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: cfg.DeviceID})
	if err != nil {
		t.Fatalf("expected EST enrollment to JITP-create device: %s", err)
	}
	if device.IdentitySlot == nil {
		t.Fatalf("expected EST enrollment to bind an identity slot")
	}

	activeSerial := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
	storedCert, err := cfg.TestServers.CA.Service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: activeSerial,
	})
	if err != nil {
		t.Fatalf("expected enrolled certificate to be stored: %s", err)
	}
	if storedCert.KeyMetadata.Type != models.KeyTypeDilithium3 {
		t.Fatalf("expected Dilithium3 key metadata, got %s", storedCert.KeyMetadata.Type.String())
	}
	if storedCert.Subject.CommonName != cfg.DeviceID {
		t.Fatalf("stored certificate subject does not match enrolled device")
	}
}

// estPOCTestHTTPClient accepts the self-signed DMS Manager test certificate so
// the test can focus on EST enrollment behavior instead of local TLS trust.
func estPOCTestHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
