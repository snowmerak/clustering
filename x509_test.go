package clustering

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func TestNewMLDSAPrivateCertificate(t *testing.T) {
	subject := pkix.Name{CommonName: "Test Subject"}
	issuer := pkix.Name{CommonName: "Test Issuer"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	privCert, err := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create private certificate: %v", err)
	}

	if privCert == nil {
		t.Fatal("Private certificate is nil")
	}

	if privCert.PrivateKey == nil {
		t.Fatal("Private key is nil")
	}

	// Verify the public certificate
	err = privCert.PublicCertificate.Verify()
	if err != nil {
		t.Fatalf("Certificate verification failed: %v", err)
	}
}

func TestNewMLDSAPublicCertificateFromPublicKey(t *testing.T) {
	subject := pkix.Name{CommonName: "Test Subject"}
	issuer := pkix.Name{CommonName: "Test Issuer"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	// Generate a key pair for signing
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	pubCert, err := NewMLDSAPublicCertificateFromPublicKey(subject, issuer, notBefore, notAfter, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create public certificate: %v", err)
	}

	if pubCert == nil {
		t.Fatal("Public certificate is nil")
	}

	// Verify the certificate
	err = pubCert.Verify()
	if err != nil {
		t.Fatalf("Certificate verification failed: %v", err)
	}
}

func TestMarshalUnmarshalPEM(t *testing.T) {
	subject := pkix.Name{CommonName: "Test Subject"}
	issuer := pkix.Name{CommonName: "Test Issuer"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	privCert, err := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create private certificate: %v", err)
	}

	pubCert := privCert.PublicCert()

	// Marshal to PEM
	pemData, err := pubCert.MarshalPEM()
	if err != nil {
		t.Fatalf("Failed to marshal to PEM: %v", err)
	}

	// Unmarshal from PEM
	unmarshaledCert, err := UnmarshalPEM(pemData)
	if err != nil {
		t.Fatalf("Failed to unmarshal from PEM: %v", err)
	}

	// Verify the unmarshaled certificate
	err = unmarshaledCert.Verify()
	if err != nil {
		t.Fatalf("Unmarshaled certificate verification failed: %v", err)
	}

	// Check if the public keys match
	// Since we can't directly compare keys, check if they produce the same signature verification
	testData := []byte("test data")
	sig, err := privCert.SignData(testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	if !pubCert.VerifyData(testData, sig) {
		t.Fatal("Original certificate failed to verify signature")
	}

	if !unmarshaledCert.VerifyData(testData, sig) {
		t.Fatal("Unmarshaled certificate failed to verify signature")
	}
}

func TestSignAndVerifyData(t *testing.T) {
	subject := pkix.Name{CommonName: "Test Subject"}
	issuer := pkix.Name{CommonName: "Test Issuer"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	privCert, err := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create private certificate: %v", err)
	}

	pubCert := privCert.PublicCert()

	testData := []byte("Hello, ML-DSA!")

	// Sign data
	sig, err := privCert.SignData(testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Verify data
	if !pubCert.VerifyData(testData, sig) {
		t.Fatal("Data verification failed")
	}

	// Test with wrong data
	wrongData := []byte("Wrong data")
	if pubCert.VerifyData(wrongData, sig) {
		t.Fatal("Verification should fail with wrong data")
	}

	// Test with wrong signature
	wrongSig := make([]byte, len(sig))
	copy(wrongSig, sig)
	wrongSig[0] ^= 1 // Flip a bit
	if pubCert.VerifyData(testData, wrongSig) {
		t.Fatal("Verification should fail with wrong signature")
	}
}

func TestGetPublicKey(t *testing.T) {
	subject := pkix.Name{CommonName: "Test Subject"}
	issuer := pkix.Name{CommonName: "Test Issuer"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	privCert, err := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create private certificate: %v", err)
	}

	pubCert := privCert.PublicCert()

	pubKey := pubCert.GetPublicKey()
	if pubKey == nil {
		t.Fatal("Public key is nil")
	}

	// Test that the public key can be used for verification
	testData := []byte("test")
	sig, err := privCert.SignData(testData)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if !mldsa87.Verify(pubKey, testData, []byte{}, sig) {
		t.Fatal("Public key verification failed")
	}
}

func TestVerifyWithKey(t *testing.T) {
	// Root CA
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootIssuer := pkix.Name{CommonName: "Root CA"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	rootPrivCert, err := NewMLDSAPrivateCertificate(rootSubject, rootIssuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}
	rootPubKey := rootPrivCert.PublicCert().GetPublicKey()

	// Subordinate certificate signed by root
	subSubject := pkix.Name{CommonName: "Sub Cert"}
	subIssuer := rootSubject

	subCert, err := NewMLDSAPublicCertificateFromPublicKey(subSubject, subIssuer, notBefore, notAfter, rootPubKey, rootPrivCert.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create subordinate certificate: %v", err)
	}

	// Verify subordinate cert with root's public key
	err = subCert.VerifyWithKey(rootPubKey)
	if err != nil {
		t.Fatalf("Verification with root key failed: %v", err)
	}

	// Test with wrong key (should fail)
	wrongPub, _, _ := mldsa87.GenerateKey(rand.Reader)
	err = subCert.VerifyWithKey(wrongPub)
	if err == nil {
		t.Fatal("Verification should fail with wrong key")
	}
}
