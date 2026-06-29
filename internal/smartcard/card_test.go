
package smartcard

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestChooseMechanismSupportsRSAEncryption(t *testing.T) {
	mechanism, err := chooseMechanism(pkix.AlgorithmIdentifier{
		Algorithm: oidRSAEncryption,
	})
	if err != nil {
		t.Fatalf("chooseMechanism returned an error: %v", err)
	}

	if mechanism.Mechanism != pkcs11.CKM_RSA_PKCS {
		t.Fatalf("expected CKM_RSA_PKCS, got %d", mechanism.Mechanism)
	}
}

func TestRSAOAEPParamsDefaultToSHA1(t *testing.T) {
	params, err := rsaOAEPParams(asn1.RawValue{})
	if err != nil {
		t.Fatalf("rsaOAEPParams returned an error: %v", err)
	}

	assertOAEPParams(t, params, pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil)
}

func TestRSAOAEPParamsEmptySequenceDefaultToSHA1(t *testing.T) {
	raw, err := asn1.Marshal(rsaOAEPAlgorithmParams{})
	if err != nil {
		t.Fatalf("could not marshal OAEP parameters: %v", err)
	}

	params, err := rsaOAEPParams(asn1.RawValue{FullBytes: raw})
	if err != nil {
		t.Fatalf("rsaOAEPParams returned an error: %v", err)
	}

	assertOAEPParams(t, params, pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil)
}

func TestRSAOAEPParamsDecodeExplicitSHA256AndSourceData(t *testing.T) {
	paramsDER := marshalRSAOAEPParams(t, oidSHA256, []byte("key-label"))

	params, err := rsaOAEPParams(asn1.RawValue{FullBytes: paramsDER})
	if err != nil {
		t.Fatalf("rsaOAEPParams returned an error: %v", err)
	}

	assertOAEPParams(t, params, pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, []byte("key-label"))
}

func TestRSAOAEPParamsRejectUnsupportedHash(t *testing.T) {
	paramsDER := marshalRSAOAEPParams(t, asn1.ObjectIdentifier{1, 2, 3, 4}, nil)

	_, err := rsaOAEPParams(asn1.RawValue{FullBytes: paramsDER})
	if err == nil {
		t.Fatal("expected unsupported hash to fail")
	}
}

func marshalRSAOAEPParams(t *testing.T, hashOID asn1.ObjectIdentifier, sourceData []byte) []byte {
	t.Helper()

	hashAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm:  hashOID,
		Parameters: asn1.NullRawValue,
	}
	hashAlgorithmDER, err := asn1.Marshal(hashAlgorithm)
	if err != nil {
		t.Fatalf("could not marshal hash algorithm: %v", err)
	}

	pSourceDER, err := asn1.Marshal(sourceData)
	if err != nil {
		t.Fatalf("could not marshal pSource data: %v", err)
	}

	params := rsaOAEPAlgorithmParams{
		HashAlgorithm: hashAlgorithm,
		MaskGenAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidMGF1,
			Parameters: asn1.RawValue{
				FullBytes: hashAlgorithmDER,
			},
		},
		PSourceAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidPSpecified,
			Parameters: asn1.RawValue{
				FullBytes: pSourceDER,
			},
		},
	}

	paramsDER, err := asn1.Marshal(params)
	if err != nil {
		t.Fatalf("could not marshal OAEP parameters: %v", err)
	}

	return paramsDER
}

func assertOAEPParams(t *testing.T, params *pkcs11.OAEPParams, hashAlg uint, mgf uint, sourceData []byte) {
	t.Helper()

	if params.HashAlg != hashAlg {
		t.Fatalf("expected hash algorithm %d, got %d", hashAlg, params.HashAlg)
	}

	if params.MGF != mgf {
		t.Fatalf("expected MGF %d, got %d", mgf, params.MGF)
	}

	if params.SourceType != pkcs11.CKZ_DATA_SPECIFIED {
		t.Fatalf("expected source type %d, got %d", pkcs11.CKZ_DATA_SPECIFIED, params.SourceType)
	}

	if string(params.SourceData) != string(sourceData) {
		t.Fatalf("expected source data %q, got %q", sourceData, params.SourceData)
	}
}
