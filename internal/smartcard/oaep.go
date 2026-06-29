package smartcard

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

var (
	oidRSAEncryption     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAOAEPEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidPSpecified        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 9}
	oidSHA1              = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

type rsaOAEPAlgorithmParams struct {
	HashAlgorithm    pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	PSourceAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:2"`
}

func rsaOAEPParams(raw asn1.RawValue) (*pkcs11.OAEPParams, error) {
	var params rsaOAEPAlgorithmParams

	if len(raw.FullBytes) > 0 && !bytes.Equal(raw.FullBytes, asn1.NullBytes) {
		rest, err := asn1.Unmarshal(raw.FullBytes, &params)
		if err != nil {
			return nil, fmt.Errorf("could not parse RSA-OAEP parameters: %w", err)
		}

		if len(rest) != 0 {
			return nil, errors.New("could not parse RSA-OAEP parameters: trailing data")
		}
	}

	hashAlg := uint(pkcs11.CKM_SHA_1)
	if len(params.HashAlgorithm.Algorithm) > 0 {
		var err error

		hashAlg, _, err = oaepHashAlgorithm(params.HashAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("unsupported RSA-OAEP hash algorithm: %w", err)
		}
	}

	mgf := uint(pkcs11.CKG_MGF1_SHA1)
	if len(params.MaskGenAlgorithm.Algorithm) > 0 {
		var err error

		mgf, err = oaepMGF(params.MaskGenAlgorithm)
		if err != nil {
			return nil, err
		}
	}

	sourceData, err := oaepSourceData(params.PSourceAlgorithm)
	if err != nil {
		return nil, err
	}

	return pkcs11.NewOAEPParams(hashAlg, mgf, pkcs11.CKZ_DATA_SPECIFIED, sourceData), nil
}

func oaepMGF(algorithm pkix.AlgorithmIdentifier) (uint, error) {
	if !algorithm.Algorithm.Equal(oidMGF1) {
		return 0, fmt.Errorf("unsupported RSA-OAEP mask generation function %s", algorithm.Algorithm)
	}

	var mgfHash pkix.AlgorithmIdentifier
	rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &mgfHash)
	if err != nil {
		return 0, fmt.Errorf("could not parse RSA-OAEP MGF1 hash algorithm: %w", err)
	}

	if len(rest) != 0 {
		return 0, errors.New("could not parse RSA-OAEP MGF1 hash algorithm: trailing data")
	}

	_, mgf, err := oaepHashAlgorithm(mgfHash)
	if err != nil {
		return 0, fmt.Errorf("unsupported RSA-OAEP MGF1 hash algorithm: %w", err)
	}

	return mgf, nil
}

func oaepSourceData(algorithm pkix.AlgorithmIdentifier) ([]byte, error) {
	if len(algorithm.Algorithm) == 0 {
		return nil, nil
	}

	if !algorithm.Algorithm.Equal(oidPSpecified) {
		return nil, fmt.Errorf("unsupported RSA-OAEP source algorithm %s", algorithm.Algorithm)
	}

	if len(algorithm.Parameters.FullBytes) == 0 {
		return nil, nil
	}

	var sourceData []byte
	rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &sourceData)
	if err != nil {
		return nil, fmt.Errorf("could not parse RSA-OAEP source data: %w", err)
	}

	if len(rest) != 0 {
		return nil, errors.New("could not parse RSA-OAEP source data: trailing data")
	}

	return sourceData, nil
}

func oaepHashAlgorithm(algorithm pkix.AlgorithmIdentifier) (uint, uint, error) {
	if len(algorithm.Parameters.FullBytes) > 0 && !bytes.Equal(algorithm.Parameters.FullBytes, asn1.NullBytes) {
		return 0, 0, fmt.Errorf("unexpected parameters for hash algorithm %s", algorithm.Algorithm)
	}

	switch {
	case algorithm.Algorithm.Equal(oidSHA1):
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil
	case algorithm.Algorithm.Equal(oidSHA224):
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, nil
	case algorithm.Algorithm.Equal(oidSHA256):
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, nil
	case algorithm.Algorithm.Equal(oidSHA384):
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, nil
	case algorithm.Algorithm.Equal(oidSHA512):
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, nil
	default:
		return 0, 0, fmt.Errorf("unsupported hash algorithm %s", algorithm.Algorithm)
	}
}
