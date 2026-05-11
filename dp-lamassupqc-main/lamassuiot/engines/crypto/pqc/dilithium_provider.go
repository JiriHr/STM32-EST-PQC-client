package pqc

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type DilithiumProvider struct{}

func NewDilithiumProvider() *DilithiumProvider {
	return &DilithiumProvider{}
}

func NewMLDSAProvider() *DilithiumProvider {
	return &DilithiumProvider{}
}

func (p *DilithiumProvider) GenerateKeyPair(alg Algorithm) (*KeyPair, error) {
	switch alg {
	case Dilithium2:
		pub, priv, err := mode2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("dilithium2 key generation failed: %w", err)
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return &KeyPair{
			Algorithm:  alg,
			PublicKey:  pubBytes,
			PrivateKey: privBytes,
		}, nil

	case Dilithium3:
		pub, priv, err := mode3.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("dilithium3 key generation failed: %w", err)
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return &KeyPair{
			Algorithm:  alg,
			PublicKey:  pubBytes,
			PrivateKey: privBytes,
		}, nil

	case Dilithium5:
		pub, priv, err := mode5.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("dilithium5 key generation failed: %w", err)
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return &KeyPair{
			Algorithm:  alg,
			PublicKey:  pubBytes,
			PrivateKey: privBytes,
		}, nil

	case MLDSA44:
		pub, priv, err := mldsa44.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("mldsa44 key generation failed: %w", err)
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return &KeyPair{
			Algorithm:  alg,
			PublicKey:  pubBytes,
			PrivateKey: privBytes,
		}, nil

	case MLDSA65:
		pub, priv, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("mldsa65 key generation failed: %w", err)
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return &KeyPair{
			Algorithm:  alg,
			PublicKey:  pubBytes,
			PrivateKey: privBytes,
		}, nil

	case MLDSA87:
		pub, priv, err := mldsa87.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("mldsa87 key generation failed: %w", err)
		}
		pubBytes, _ := pub.MarshalBinary()
		privBytes, _ := priv.MarshalBinary()
		return &KeyPair{
			Algorithm:  alg,
			PublicKey:  pubBytes,
			PrivateKey: privBytes,
		}, nil

	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func (p *DilithiumProvider) Sign(data []byte, privateKey []byte, alg Algorithm) ([]byte, error) {
	switch alg {
	case Dilithium2:
		var priv mode2.PrivateKey
		if err := priv.UnmarshalBinary(privateKey); err != nil {
			return nil, fmt.Errorf("invalid dilithium2 private key: %w", err)
		}
		return priv.Sign(nil, data, nil)

	case Dilithium3:
		var priv mode3.PrivateKey
		if err := priv.UnmarshalBinary(privateKey); err != nil {
			return nil, fmt.Errorf("invalid dilithium3 private key: %w", err)
		}
		return priv.Sign(nil, data, nil)

	case Dilithium5:
		var priv mode5.PrivateKey
		if err := priv.UnmarshalBinary(privateKey); err != nil {
			return nil, fmt.Errorf("invalid dilithium5 private key: %w", err)
		}
		return priv.Sign(nil, data, nil)

	case MLDSA44:
		var priv mldsa44.PrivateKey
		if err := priv.UnmarshalBinary(privateKey); err != nil {
			return nil, fmt.Errorf("invalid mldsa44 private key: %w", err)
		}
		return priv.Sign(nil, data, nil)

	case MLDSA65:
		var priv mldsa65.PrivateKey
		if err := priv.UnmarshalBinary(privateKey); err != nil {
			return nil, fmt.Errorf("invalid mldsa65 private key: %w", err)
		}
		return priv.Sign(nil, data, nil)

	case MLDSA87:
		var priv mldsa87.PrivateKey
		if err := priv.UnmarshalBinary(privateKey); err != nil {
			return nil, fmt.Errorf("invalid mldsa87 private key: %w", err)
		}
		return priv.Sign(nil, data, nil)

	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func (p *DilithiumProvider) Verify(data []byte, signature []byte, publicKey []byte, alg Algorithm) (bool, error) {
	switch alg {
	case Dilithium2:
		var pub mode2.PublicKey
		if err := pub.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("invalid dilithium2 public key: %w", err)
		}
		return mode2.Verify(&pub, data, signature), nil

	case Dilithium3:
		var pub mode3.PublicKey
		if err := pub.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("invalid dilithium3 public key: %w", err)
		}
		return mode3.Verify(&pub, data, signature), nil

	case Dilithium5:
		var pub mode5.PublicKey
		if err := pub.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("invalid dilithium5 public key: %w", err)
		}
		return mode5.Verify(&pub, data, signature), nil

	case MLDSA44:
		var pub mldsa44.PublicKey
		if err := pub.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("invalid mldsa44 public key: %w", err)
		}
		return mldsa44.Verify(&pub, data, nil, signature), nil

	case MLDSA65:
		var pub mldsa65.PublicKey
		if err := pub.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("invalid mldsa65 public key: %w", err)
		}
		return mldsa65.Verify(&pub, data, nil, signature), nil

	case MLDSA87:
		var pub mldsa87.PublicKey
		if err := pub.UnmarshalBinary(publicKey); err != nil {
			return false, fmt.Errorf("invalid mldsa87 public key: %w", err)
		}
		return mldsa87.Verify(&pub, data, nil, signature), nil

	default:
		return false, ErrUnsupportedAlgorithm
	}
}

func (p *DilithiumProvider) PublicKeySize(alg Algorithm) int {
	switch alg {
	case Dilithium2:
		return mode2.PublicKeySize
	case Dilithium3:
		return mode3.PublicKeySize
	case Dilithium5:
		return mode5.PublicKeySize
	case MLDSA44:
		return mldsa44.PublicKeySize
	case MLDSA65:
		return mldsa65.PublicKeySize
	case MLDSA87:
		return mldsa87.PublicKeySize
	default:
		return 0
	}
}

func (p *DilithiumProvider) PrivateKeySize(alg Algorithm) int {
	switch alg {
	case Dilithium2:
		return mode2.PrivateKeySize
	case Dilithium3:
		return mode3.PrivateKeySize
	case Dilithium5:
		return mode5.PrivateKeySize
	case MLDSA44:
		return mldsa44.PrivateKeySize
	case MLDSA65:
		return mldsa65.PrivateKeySize
	case MLDSA87:
		return mldsa87.PrivateKeySize
	default:
		return 0
	}
}

func (p *DilithiumProvider) SignatureSize(alg Algorithm) int {
	switch alg {
	case Dilithium2:
		return mode2.SignatureSize
	case Dilithium3:
		return mode3.SignatureSize
	case Dilithium5:
		return mode5.SignatureSize
	case MLDSA44:
		return mldsa44.SignatureSize
	case MLDSA65:
		return mldsa65.SignatureSize
	case MLDSA87:
		return mldsa87.SignatureSize
	default:
		return 0
	}
}
