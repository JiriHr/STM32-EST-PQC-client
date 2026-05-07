package helpers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
	"unicode"

	"github.com/lamassuiot/lamassuiot/engines/crypto/pqc"
)

var (
	oidExtensionSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionRequest          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidExtKeyUsageServerAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidSignatureSHA256WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureECDSAWithSHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

type customSubjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type customTBSCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"explicit,tag:0,default:2"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           customValidity
	Subject            asn1.RawValue
	PublicKey          customSubjectPublicKeyInfo
	Extensions         []pkix.Extension `asn1:"explicit,optional,tag:3"`
}

type customCertificate struct {
	TBSCertificate     customTBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type customValidity struct {
	NotBefore asn1.RawValue
	NotAfter  asn1.RawValue
}

type customCertificateRequestInfo struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     customSubjectPublicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type customCertificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             customCertificateRequestInfo
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type authorityKeyIdentifier struct {
	ID []byte `asn1:"tag:0,optional"`
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

type noHashSignerOpts struct{}

func (noHashSignerOpts) HashFunc() crypto.Hash {
	return crypto.Hash(0)
}

func CreateCertificate(template, parent *x509.Certificate, publicKey crypto.PublicKey, signer crypto.Signer, algorithm string) (*x509.Certificate, error) {
	signatureAlgorithm, hashFunc, err := signatureAlgorithmIdentifier(algorithm)
	if err != nil {
		return nil, err
	}

	subjectBytes, err := marshalName(template.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate subject: %w", err)
	}

	issuerBytes, err := marshalCertificateName(parent, parent.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate issuer: %w", err)
	}

	publicKeyInfo, rawPublicKeyBytes, err := marshalSubjectPublicKeyInfo(publicKey, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate public key: %w", err)
	}

	subjectKeyID := template.SubjectKeyId
	if len(subjectKeyID) == 0 {
		subjectKeyID = defaultSubjectKeyID(rawPublicKeyBytes)
	}

	authorityKeyID := template.AuthorityKeyId
	if len(authorityKeyID) == 0 && parent != nil && len(parent.SubjectKeyId) > 0 && !sameNameDER(subjectBytes, issuerBytes) {
		authorityKeyID = parent.SubjectKeyId
	}

	extensions, err := buildCustomCertificateExtensions(template, authorityKeyID, subjectKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate extensions: %w", err)
	}

	serialRaw, err := asn1.Marshal(template.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate serial number: %w", err)
	}

	tbs := customTBSCertificate{
		Version:            2,
		SerialNumber:       asn1.RawValue{FullBytes: serialRaw},
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: issuerBytes},
		Validity: customValidity{
			NotBefore: marshalASN1Time(template.NotBefore),
			NotAfter:  marshalASN1Time(template.NotAfter),
		},
		Subject:    asn1.RawValue{FullBytes: subjectBytes},
		PublicKey:  publicKeyInfo,
		Extensions: extensions,
	}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}
	tbs.Raw = tbsDER

	signature, err := signBytes(tbsDER, signer, hashFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	certDER, err := asn1.Marshal(customCertificate{
		TBSCertificate:     tbs,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse custom certificate: %w", err)
	}

	if IsPQCAlgorithm(detectPublicKeyAlgorithm(rawPublicKeyBytes, publicKeyInfo.Algorithm.Algorithm)) {
		cert.PublicKey = publicKey
		cert.PublicKeyAlgorithm = pqcPublicKeyAlgorithm(detectPublicKeyAlgorithm(rawPublicKeyBytes, publicKeyInfo.Algorithm.Algorithm))
	}
	if len(cert.SubjectKeyId) == 0 {
		cert.SubjectKeyId = append([]byte(nil), subjectKeyID...)
	}
	if len(cert.AuthorityKeyId) == 0 {
		cert.AuthorityKeyId = append([]byte(nil), authorityKeyID...)
	}

	return cert, nil
}

func CreateCertificateRequest(template *x509.CertificateRequest, signer crypto.Signer, algorithm string) (*x509.CertificateRequest, error) {
	signatureAlgorithm, hashFunc, err := signatureAlgorithmIdentifier(algorithm)
	if err != nil {
		return nil, err
	}

	subjectBytes, err := marshalName(template.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSR subject: %w", err)
	}

	publicKeyInfo, _, err := marshalSubjectPublicKeyInfo(signer.Public(), algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSR public key: %w", err)
	}

	rawAttributes := []asn1.RawValue{}
	if len(template.ExtraExtensions) > 0 {
		attributeDER, err := asn1.Marshal(struct {
			Type  asn1.ObjectIdentifier
			Value [][]pkix.Extension `asn1:"set"`
		}{
			Type:  oidExtensionRequest,
			Value: [][]pkix.Extension{template.ExtraExtensions},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal CSR extension request attribute: %w", err)
		}
		rawAttributes = append(rawAttributes, asn1.RawValue{FullBytes: attributeDER})
	}

	tbs := customCertificateRequestInfo{
		Version:       0,
		Subject:       asn1.RawValue{FullBytes: subjectBytes},
		PublicKey:     publicKeyInfo,
		RawAttributes: rawAttributes,
	}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CertificationRequestInfo: %w", err)
	}
	tbs.Raw = tbsDER

	signature, err := signBytes(tbsDER, signer, hashFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate request: %w", err)
	}

	csrDER, err := asn1.Marshal(customCertificateRequest{
		TBSCSR:             tbs,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate request: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse custom certificate request: %w", err)
	}

	if IsPQCAlgorithm(algorithm) {
		csr.PublicKey = signer.Public()
		csr.PublicKeyAlgorithm = pqcPublicKeyAlgorithm(algorithm)
	}

	return csr, nil
}

func VerifyCertificateRequestSignature(csr *x509.CertificateRequest) error {
	// Classical CSRs can stay on the stdlib verification path.
	if csr.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		if err := csr.CheckSignature(); err == nil {
			return nil
		}
	}

	algorithm, publicKeyBytes, err := ExtractPQCPublicKeyFromSPKI(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return fmt.Errorf("invalid CSR signature: %w", err)
	}

	signatureAlgorithm, err := extractCSRSignatureAlgorithm(csr.Raw)
	if err != nil {
		return fmt.Errorf("invalid CSR signature algorithm: %w", err)
	}
	if signatureAlgorithm != algorithm {
		return fmt.Errorf("invalid CSR signature: subject public key algorithm %s does not match signature algorithm %s", algorithm, signatureAlgorithm)
	}

	provider := pqc.NewDilithiumProvider()
	valid, err := provider.Verify(csr.RawTBSCertificateRequest, csr.Signature, publicKeyBytes, dilithiumPQCAlgorithm(algorithm))
	if err != nil {
		return fmt.Errorf("invalid CSR signature: %w", err)
	}
	if !valid {
		return errors.New("invalid CSR signature")
	}

	return nil
}

func ExtractDilithiumPublicKeyFromSPKI(rawSPKI []byte) (string, []byte, error) {
	algorithm, publicKey, err := ExtractPQCPublicKeyFromSPKI(rawSPKI)
	if err != nil {
		return "", nil, err
	}
	if !IsDilithiumAlgorithm(algorithm) {
		return "", nil, fmt.Errorf("subject public key is %s, not Dilithium", algorithm)
	}
	return algorithm, publicKey, nil
}

func ExtractPQCPublicKeyFromSPKI(rawSPKI []byte) (string, []byte, error) {
	if len(rawSPKI) == 0 {
		return "", nil, errors.New("empty subject public key info")
	}

	var spki customSubjectPublicKeyInfo
	if _, err := asn1.Unmarshal(rawSPKI, &spki); err != nil {
		return "", nil, fmt.Errorf("failed to parse subject public key info: %w", err)
	}

	algorithm, err := GetPQCAlgorithmFromOID(spki.Algorithm.Algorithm)
	if err != nil {
		return "", nil, err
	}

	return algorithm, append([]byte(nil), spki.PublicKey.Bytes...), nil
}

func SupportsCustomX509CertificateCreation(algorithm string, publicKey crypto.PublicKey) bool {
	if IsPQCAlgorithm(algorithm) {
		return true
	}

	_, _, err := marshalSubjectPublicKeyInfo(publicKey)
	return err == nil && isPQCPublicKey(publicKey)
}

func SigningAlgorithmFromPublicKey(publicKey crypto.PublicKey) (string, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		switch key.N.BitLen() {
		case 2048:
			return "RSA_2048", nil
		case 3072:
			return "RSA_3072", nil
		case 4096:
			return "RSA_4096", nil
		default:
			return "", fmt.Errorf("unsupported RSA key size: %d", key.N.BitLen())
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 256:
			return "ECDSA_P256", nil
		case 384:
			return "ECDSA_P384", nil
		case 521:
			return "ECDSA_P521", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve size: %d", key.Curve.Params().BitSize)
		}
	}

	if algorithm, _, ok := extractPQCPublicKey(publicKey); ok {
		return algorithm, nil
	}

	return "", fmt.Errorf("unsupported public key type %T", publicKey)
}

// DilithiumModeFromPublicKey reports the Dilithium mode encoded in a raw or
// marshalable public key. The EST POC uses this when issuance profiles enforce
// PQC key families, because stdlib x509 does not classify Dilithium keys.
func DilithiumModeFromPublicKey(publicKey crypto.PublicKey) (int, bool) {
	algorithm, _, ok := extractPQCPublicKey(publicKey)
	if !ok {
		return 0, false
	}

	switch algorithm {
	case "DILITHIUM_2", "DILITHIUM2":
		return 2, true
	case "DILITHIUM_3", "DILITHIUM3":
		return 3, true
	case "DILITHIUM_5", "DILITHIUM5":
		return 5, true
	default:
		return 0, false
	}
}

func MLDSASecurityVersionFromPublicKey(publicKey crypto.PublicKey) (int, bool) {
	algorithm, _, ok := extractPQCPublicKey(publicKey)
	if !ok {
		return 0, false
	}

	switch algorithm {
	case "ML_DSA_44", "MLDSA44", "ML-DSA-44":
		return 44, true
	case "ML_DSA_65", "MLDSA65", "ML-DSA-65":
		return 65, true
	case "ML_DSA_87", "MLDSA87", "ML-DSA-87":
		return 87, true
	default:
		return 0, false
	}
}

func SubjectKeyIDFromPublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	_, rawPublicKey, err := marshalSubjectPublicKeyInfo(publicKey)
	if err != nil {
		return nil, err
	}
	return defaultSubjectKeyID(rawPublicKey), nil
}

func SubjectKeyIDFromSPKI(rawSPKI []byte) ([]byte, error) {
	if len(rawSPKI) == 0 {
		return nil, errors.New("empty subject public key info")
	}

	var spki customSubjectPublicKeyInfo
	if _, err := asn1.Unmarshal(rawSPKI, &spki); err != nil {
		return nil, err
	}

	return defaultSubjectKeyID(spki.PublicKey.Bytes), nil
}

func marshalSubjectPublicKeyInfo(publicKey crypto.PublicKey, preferredAlgorithm ...string) (customSubjectPublicKeyInfo, []byte, error) {
	if len(preferredAlgorithm) > 0 && IsPQCAlgorithm(preferredAlgorithm[0]) {
		rawPublicKey, ok := extractPublicKeyBytes(publicKey)
		if !ok {
			return customSubjectPublicKeyInfo{}, nil, fmt.Errorf("unsupported PQC public key type %T", publicKey)
		}

		algorithmIdentifier, err := CreatePQCSignatureAlgorithm(preferredAlgorithm[0])
		if err != nil {
			return customSubjectPublicKeyInfo{}, nil, err
		}

		return customSubjectPublicKeyInfo{
			Algorithm: algorithmIdentifier,
			PublicKey: asn1.BitString{
				Bytes:     rawPublicKey,
				BitLength: len(rawPublicKey) * 8,
			},
		}, rawPublicKey, nil
	}

	if algorithm, rawPublicKey, ok := extractPQCPublicKey(publicKey); ok {
		algorithmIdentifier, err := CreatePQCSignatureAlgorithm(algorithm)
		if err != nil {
			return customSubjectPublicKeyInfo{}, nil, err
		}

		return customSubjectPublicKeyInfo{
			Algorithm: algorithmIdentifier,
			PublicKey: asn1.BitString{
				Bytes:     rawPublicKey,
				BitLength: len(rawPublicKey) * 8,
			},
		}, rawPublicKey, nil
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return customSubjectPublicKeyInfo{}, nil, err
	}

	var spki customSubjectPublicKeyInfo
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return customSubjectPublicKeyInfo{}, nil, err
	}

	return spki, append([]byte(nil), spki.PublicKey.Bytes...), nil
}

func buildCustomCertificateExtensions(template *x509.Certificate, authorityKeyID, subjectKeyID []byte) ([]pkix.Extension, error) {
	extensions := make([]pkix.Extension, 0, 8+len(template.ExtraExtensions))

	if template.KeyUsage != 0 && !hasExtension(template.ExtraExtensions, oidExtensionKeyUsage) {
		extension, err := marshalKeyUsageExtension(template.KeyUsage)
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, extension)
	}

	if len(template.ExtKeyUsage) > 0 && !hasExtension(template.ExtraExtensions, oidExtensionExtendedKeyUsage) {
		extension, err := marshalExtKeyUsageExtension(template.ExtKeyUsage)
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, extension)
	}

	if template.BasicConstraintsValid && !hasExtension(template.ExtraExtensions, oidExtensionBasicConstraints) {
		extension, err := marshalBasicConstraintsExtension(template.IsCA, template.MaxPathLen, template.MaxPathLenZero)
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, extension)
	}

	if len(subjectKeyID) > 0 && !hasExtension(template.ExtraExtensions, oidExtensionSubjectKeyID) {
		value, err := asn1.Marshal(subjectKeyID)
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, pkix.Extension{Id: oidExtensionSubjectKeyID, Value: value})
	}

	if len(authorityKeyID) > 0 && !hasExtension(template.ExtraExtensions, oidExtensionAuthorityKeyID) {
		value, err := asn1.Marshal(authorityKeyIdentifier{ID: authorityKeyID})
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, pkix.Extension{Id: oidExtensionAuthorityKeyID, Value: value})
	}

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!hasExtension(template.ExtraExtensions, oidExtensionSubjectAltName) {
		value, err := marshalSANExtension(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, pkix.Extension{Id: oidExtensionSubjectAltName, Value: value})
	}

	extensions = append(extensions, template.ExtraExtensions...)
	return extensions, nil
}

func signatureAlgorithmIdentifier(algorithm string) (pkix.AlgorithmIdentifier, crypto.Hash, error) {
	switch algorithm {
	case "RSA_2048", "RSA_3072", "RSA_4096":
		return pkix.AlgorithmIdentifier{Algorithm: oidSignatureSHA256WithRSA, Parameters: asn1.NullRawValue}, crypto.SHA256, nil
	case "ECDSA_P256":
		return pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA256}, crypto.SHA256, nil
	case "ECDSA_P384":
		return pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA384}, crypto.SHA384, nil
	case "ECDSA_P521":
		return pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA512}, crypto.SHA512, nil
	default:
		if IsPQCAlgorithm(algorithm) {
			ai, err := CreatePQCSignatureAlgorithm(algorithm)
			return ai, crypto.Hash(0), err
		}
		return pkix.AlgorithmIdentifier{}, 0, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
}

func signBytes(tbsDER []byte, signer crypto.Signer, hashFunc crypto.Hash) ([]byte, error) {
	message := tbsDER
	var opts crypto.SignerOpts = noHashSignerOpts{}

	if hashFunc != crypto.Hash(0) {
		hasher := hashFunc.New()
		if _, err := hasher.Write(tbsDER); err != nil {
			return nil, err
		}
		message = hasher.Sum(nil)
		opts = hashFunc
	}

	return signer.Sign(nil, message, opts)
}

func marshalName(name pkix.Name) ([]byte, error) {
	return asn1.Marshal(name.ToRDNSequence())
}

func marshalCertificateName(cert *x509.Certificate, fallback pkix.Name) ([]byte, error) {
	if cert != nil && len(cert.RawSubject) > 0 {
		return append([]byte(nil), cert.RawSubject...), nil
	}
	return marshalName(fallback)
}

func marshalASN1Time(t time.Time) asn1.RawValue {
	t = t.UTC()
	format := "060102150405Z"
	tag := 23
	if t.Year() >= 2050 || t.Year() < 1950 {
		format = "20060102150405Z"
		tag = 24
	}
	return asn1.RawValue{Class: 0, Tag: tag, Bytes: []byte(t.Format(format))}
}

func marshalKeyUsageExtension(usage x509.KeyUsage) (pkix.Extension, error) {
	var encoded [2]byte
	encoded[0] = reverseBitsInAByte(byte(usage))
	encoded[1] = reverseBitsInAByte(byte(usage >> 8))

	length := 1
	if encoded[1] != 0 {
		length = 2
	}

	bitString := encoded[:length]
	value, err := asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{Id: oidExtensionKeyUsage, Critical: true, Value: value}, nil
}

func marshalExtKeyUsageExtension(usages []x509.ExtKeyUsage) (pkix.Extension, error) {
	oids := make([]asn1.ObjectIdentifier, 0, len(usages))
	for _, usage := range usages {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			oids = append(oids, oidExtKeyUsageServerAuth)
		case x509.ExtKeyUsageClientAuth:
			oids = append(oids, oidExtKeyUsageClientAuth)
		default:
			return pkix.Extension{}, fmt.Errorf("unsupported extended key usage: %d", usage)
		}
	}

	value, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{Id: oidExtensionExtendedKeyUsage, Value: value}, nil
}

func marshalBasicConstraintsExtension(isCA bool, maxPathLen int, maxPathLenZero bool) (pkix.Extension, error) {
	if maxPathLen == 0 && !maxPathLenZero {
		maxPathLen = -1
	}

	value, err := asn1.Marshal(basicConstraints{IsCA: isCA, MaxPathLen: maxPathLen})
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{Id: oidExtensionBasicConstraints, Critical: true, Value: value}, nil
}

func marshalSANExtension(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) ([]byte, error) {
	rawValues := make([]asn1.RawValue, 0, len(dnsNames)+len(emailAddresses)+len(ipAddresses)+len(uris))

	for _, name := range dnsNames {
		if err := ensureIA5String(name); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}

	for _, email := range emailAddresses {
		if err := ensureIA5String(email); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}

	for _, rawIP := range ipAddresses {
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}

	for _, uri := range uris {
		uriString := uri.String()
		if err := ensureIA5String(uriString); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uriString)})
	}

	return asn1.Marshal(rawValues)
}

func ensureIA5String(value string) error {
	for _, r := range value {
		if r > unicode.MaxASCII {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", value)
		}
	}
	return nil
}

func hasExtension(extensions []pkix.Extension, oid asn1.ObjectIdentifier) bool {
	for _, extension := range extensions {
		if extension.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func defaultSubjectKeyID(publicKey []byte) []byte {
	digest := sha1.Sum(publicKey)
	return digest[:]
}

func sameNameDER(left, right []byte) bool {
	return string(left) == string(right)
}

func reverseBitsInAByte(value byte) byte {
	value = (value&0xF0)>>4 | (value&0x0F)<<4
	value = (value&0xCC)>>2 | (value&0x33)<<2
	value = (value&0xAA)>>1 | (value&0x55)<<1
	return value
}

func asn1BitLength(bytes []byte) int {
	bitLength := len(bytes) * 8
	for len(bytes) > 0 && bytes[len(bytes)-1] == 0 {
		bytes = bytes[:len(bytes)-1]
		bitLength -= 8
	}
	if len(bytes) == 0 {
		return 0
	}
	last := bytes[len(bytes)-1]
	for i := 0; i < 8; i++ {
		if last&(1<<i) != 0 {
			break
		}
		bitLength--
	}
	return bitLength
}

func extractPublicKeyBytes(publicKey any) ([]byte, bool) {
	switch key := publicKey.(type) {
	case PQCPublicKey:
		return append([]byte(nil), key.Bytes...), len(key.Bytes) > 0
	case *PQCPublicKey:
		if key == nil {
			return nil, false
		}
		return append([]byte(nil), key.Bytes...), len(key.Bytes) > 0
	case []byte:
		return append([]byte(nil), key...), len(key) > 0
	case string:
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, false
		}
		return decoded, len(decoded) > 0
	case interface{ MarshalBinary() ([]byte, error) }:
		encoded, err := key.MarshalBinary()
		if err != nil {
			return nil, false
		}
		return encoded, len(encoded) > 0
	default:
		return nil, false
	}
}

func extractPQCPublicKey(publicKey any) (string, []byte, bool) {
	switch key := publicKey.(type) {
	case PQCPublicKey:
		if !IsPQCAlgorithm(key.Algorithm) || len(key.Bytes) == 0 {
			return "", nil, false
		}
		return key.Algorithm, append([]byte(nil), key.Bytes...), true
	case *PQCPublicKey:
		if key == nil || !IsPQCAlgorithm(key.Algorithm) || len(key.Bytes) == 0 {
			return "", nil, false
		}
		return key.Algorithm, append([]byte(nil), key.Bytes...), true
	case []byte:
		algorithm, ok := guessDilithiumAlgorithmByPublicKeySize(len(key))
		if !ok {
			return "", nil, false
		}
		return algorithm, append([]byte(nil), key...), true
	case string:
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return "", nil, false
		}
		algorithm, ok := guessDilithiumAlgorithmByPublicKeySize(len(decoded))
		if !ok {
			return "", nil, false
		}
		return algorithm, decoded, true
	case interface{ MarshalBinary() ([]byte, error) }:
		encoded, err := key.MarshalBinary()
		if err != nil {
			return "", nil, false
		}
		algorithm, ok := guessDilithiumAlgorithmByPublicKeySize(len(encoded))
		if !ok {
			return "", nil, false
		}
		return algorithm, encoded, true
	default:
		return "", nil, false
	}
}

func isDilithiumPublicKey(publicKey any) bool {
	algorithm, _, ok := extractPQCPublicKey(publicKey)
	return ok && IsDilithiumAlgorithm(algorithm)
}

func isPQCPublicKey(publicKey any) bool {
	_, _, ok := extractPQCPublicKey(publicKey)
	return ok
}

func guessDilithiumAlgorithmByPublicKeySize(size int) (string, bool) {
	switch size {
	case 1312:
		return "DILITHIUM_2", true
	case 1952:
		return "DILITHIUM_3", true
	case 2592:
		return "DILITHIUM_5", true
	default:
		return "", false
	}
}

func extractCSRSignatureAlgorithm(rawCSR []byte) (string, error) {
	var request customCertificateRequest
	if _, err := asn1.Unmarshal(rawCSR, &request); err != nil {
		return "", fmt.Errorf("failed to parse raw CSR: %w", err)
	}

	return GetPQCAlgorithmFromOID(request.SignatureAlgorithm.Algorithm)
}

func detectPublicKeyAlgorithm(rawPublicKey []byte, oid asn1.ObjectIdentifier) string {
	if algorithm, err := GetPQCAlgorithmFromOID(oid); err == nil {
		return algorithm
	}

	algorithm, _ := guessDilithiumAlgorithmByPublicKeySize(len(rawPublicKey))
	return algorithm
}

func dilithiumPublicKeyAlgorithm(algorithm string) x509.PublicKeyAlgorithm {
	return pqcPublicKeyAlgorithm(algorithm)
}

func pqcPublicKeyAlgorithm(algorithm string) x509.PublicKeyAlgorithm {
	switch algorithm {
	case "DILITHIUM_2", "DILITHIUM2":
		return x509.PublicKeyAlgorithm(100)
	case "DILITHIUM_3", "DILITHIUM3":
		return x509.PublicKeyAlgorithm(101)
	case "DILITHIUM_5", "DILITHIUM5":
		return x509.PublicKeyAlgorithm(102)
	case "ML_DSA_44", "MLDSA44", "ML-DSA-44":
		return x509.PublicKeyAlgorithm(103)
	case "ML_DSA_65", "MLDSA65", "ML-DSA-65":
		return x509.PublicKeyAlgorithm(104)
	case "ML_DSA_87", "MLDSA87", "ML-DSA-87":
		return x509.PublicKeyAlgorithm(105)
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

func dilithiumPQCAlgorithm(algorithm string) pqc.Algorithm {
	return pqcAlgorithm(algorithm)
}

func pqcAlgorithm(algorithm string) pqc.Algorithm {
	switch algorithm {
	case "DILITHIUM_2", "DILITHIUM2":
		return pqc.Dilithium2
	case "DILITHIUM_3", "DILITHIUM3":
		return pqc.Dilithium3
	case "DILITHIUM_5", "DILITHIUM5":
		return pqc.Dilithium5
	case "ML_DSA_44", "MLDSA44", "ML-DSA-44":
		return pqc.MLDSA44
	case "ML_DSA_65", "MLDSA65", "ML-DSA-65":
		return pqc.MLDSA65
	case "ML_DSA_87", "MLDSA87", "ML-DSA-87":
		return pqc.MLDSA87
	default:
		return ""
	}
}
