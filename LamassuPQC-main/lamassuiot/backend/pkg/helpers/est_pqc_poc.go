package helpers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/pqc"
)

type DilithiumCSRMaterial struct {
	CSR        *x509.CertificateRequest
	Signer     crypto.Signer
	PublicKey  []byte
	PrivateKey []byte
	Algorithm  pqc.Algorithm
}

type dilithiumSigner struct {
	provider   pqc.Provider
	algorithm  pqc.Algorithm
	publicKey  []byte
	privateKey []byte
}

func (s *dilithiumSigner) Public() crypto.PublicKey {
	return NewPQCPublicKey(pqcX509AlgorithmName(s.algorithm), s.publicKey)
}

func (s *dilithiumSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.provider.Sign(digest, s.privateKey, s.algorithm)
}

// NewDilithiumSigner adapts Lamassu's raw Dilithium key material to
// crypto.Signer. This keeps the EST POC device-side CSR generation on the same
// signing interface used by the CA/KMS code paths.
func NewDilithiumSigner(algorithm pqc.Algorithm, publicKey, privateKey []byte) crypto.Signer {
	return &dilithiumSigner{
		provider:   pqc.NewDilithiumProvider(),
		algorithm:  algorithm,
		publicKey:  append([]byte(nil), publicKey...),
		privateKey: append([]byte(nil), privateKey...),
	}
}

// CreateDilithiumCertificateRequest creates a self-signed PKCS#10 request for
// a simulated PQC device. It intentionally returns the key material too so a POC
// caller can keep behaving like a real device after EST enrollment.
func CreateDilithiumCertificateRequest(subject models.Subject, algorithm pqc.Algorithm) (*DilithiumCSRMaterial, error) {
	provider := pqc.NewDilithiumProvider()
	keyPair, err := provider.GenerateKeyPair(algorithm)
	if err != nil {
		return nil, err
	}

	signer := NewDilithiumSigner(algorithm, keyPair.PublicKey, keyPair.PrivateKey)
	csr, err := CreateCertificateRequest(&x509.CertificateRequest{
		Subject: chelpers.SubjectToPkixName(subject),
	}, signer, pqcX509AlgorithmName(algorithm))
	if err != nil {
		return nil, err
	}

	return &DilithiumCSRMaterial{
		CSR:        csr,
		Signer:     signer,
		PublicKey:  append([]byte(nil), keyPair.PublicKey...),
		PrivateKey: append([]byte(nil), keyPair.PrivateKey...),
		Algorithm:  algorithm,
	}, nil
}

func CreateMLDSACertificateRequest(subject models.Subject, algorithm pqc.Algorithm) (*DilithiumCSRMaterial, error) {
	return CreateDilithiumCertificateRequest(subject, algorithm)
}

// ESTSimpleEnrollPEM posts a CSR to Lamassu's EST simpleenroll endpoint and
// asks for a PEM certificate response. Requesting PEM avoids client-side PKCS#7
// tooling so the proof of concept stays small and focused on issuance.
func ESTSimpleEnrollPEM(ctx context.Context, httpClient *http.Client, baseURL, dmsID string, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if csr == nil {
		return nil, fmt.Errorf("csr is required")
	}

	body := base64.StdEncoding.EncodeToString(csr.Raw)
	url := fmt.Sprintf("%s/.well-known/est/%s/simpleenroll", strings.TrimRight(baseURL, "/"), dmsID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Accept", "application/x-pem-file")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("est simpleenroll failed with status %d: %s", resp.StatusCode, string(responseBody))
	}

	block, _ := pem.Decode(responseBody)
	if block == nil {
		return nil, fmt.Errorf("est simpleenroll response did not contain a PEM certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

// dilithiumX509AlgorithmName maps the PQC provider constants to the canonical
// names used by the custom X.509 encoder.
func dilithiumX509AlgorithmName(algorithm pqc.Algorithm) string {
	return pqcX509AlgorithmName(algorithm)
}

func pqcX509AlgorithmName(algorithm pqc.Algorithm) string {
	switch algorithm {
	case pqc.Dilithium2:
		return "DILITHIUM_2"
	case pqc.Dilithium3:
		return "DILITHIUM_3"
	case pqc.Dilithium5:
		return "DILITHIUM_5"
	case pqc.MLDSA44:
		return "ML_DSA_44"
	case pqc.MLDSA65:
		return "ML_DSA_65"
	case pqc.MLDSA87:
		return "ML_DSA_87"
	default:
		return string(algorithm)
	}
}
