package helpers

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/engines/crypto/pqc"
)

func ValidateCertificate(ca, cert *x509.Certificate, considerExpiration bool) error {
	// PQC certificates need a custom verification path because Go's stdlib
	// x509 verifier does not understand the PQC public key representation.
	if usesCustomPQCVerification(ca, cert) {
		if err := VerifyCertificateSignature(ca, cert); err != nil {
			return err
		}

		if considerExpiration {
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return fmt.Errorf("certificate is not valid at %s", now.UTC().Format(time.RFC3339))
			}
		}

		return nil
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if !considerExpiration {
		opts.CurrentTime = cert.NotBefore //set to same date as certificate, otherwise expired certificates will trigger Verify error
	}
	_, err := cert.Verify(opts)
	if err != nil {
		return err
	}

	return nil
}

func VerifyCertificateSignature(parent, cert *x509.Certificate) error {
	if parent == nil || cert == nil {
		return errors.New("certificate and parent certificate are required")
	}

	if !usesCustomPQCVerification(parent, cert) {
		return cert.CheckSignatureFrom(parent)
	}

	algorithm, publicKeyBytes, err := ExtractPQCPublicKeyFromSPKI(parent.RawSubjectPublicKeyInfo)
	if err != nil {
		return fmt.Errorf("failed to extract PQC issuer public key: %w", err)
	}

	provider := pqc.NewDilithiumProvider()
	valid, err := provider.Verify(cert.RawTBSCertificate, cert.Signature, publicKeyBytes, pqcAlgorithm(algorithm))
	if err != nil {
		return fmt.Errorf("failed to verify PQC certificate signature: %w", err)
	}
	if !valid {
		return errors.New("invalid PQC certificate signature")
	}

	return nil
}

func usesCustomPQCVerification(certificates ...*x509.Certificate) bool {
	for _, cert := range certificates {
		if cert == nil {
			continue
		}

		if _, _, err := ExtractPQCPublicKeyFromSPKI(cert.RawSubjectPublicKeyInfo); err == nil {
			return true
		}
	}

	return false
}
