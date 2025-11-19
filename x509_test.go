package clustering

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"os"
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

func TestParseCertificateChain(t *testing.T) {
	// Create a chain: Intermediate -> Root
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootIssuer := pkix.Name{CommonName: "Root CA"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	rootPrivCert, err := NewMLDSAPrivateCertificate(rootSubject, rootIssuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}

	interSubject := pkix.Name{CommonName: "Intermediate CA"}
	interIssuer := rootSubject

	interPrivCert, err := NewMLDSAPrivateCertificate(interSubject, interIssuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}

	interPubCert, err := NewMLDSAPublicCertificateFromPublicKey(
		interSubject, interIssuer, notBefore, notAfter,
		interPrivCert.PublicCert().GetPublicKey(), rootPrivCert.PrivateKey,
	)
	if err != nil {
		t.Fatalf("Failed to create intermediate cert: %v", err)
	}

	// Create PEM data with both certificates
	rootPEM, _ := rootPrivCert.PublicCert().MarshalPEM()
	interPEM, _ := interPubCert.MarshalPEM()

	combinedPEM := append(interPEM, rootPEM...)

	// Parse chain
	chain, err := ParseCertificateChain(combinedPEM)
	if err != nil {
		t.Fatalf("Failed to parse certificate chain: %v", err)
	}

	if len(chain) != 2 {
		t.Fatalf("Expected 2 certificates, got %d", len(chain))
	}

	// Verify chain
	err = VerifyChain(chain)
	if err != nil {
		t.Fatalf("Chain verification failed: %v", err)
	}
}

func TestVerifyChain(t *testing.T) {
	// Create valid chain
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootIssuer := pkix.Name{CommonName: "Root CA"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	rootPrivCert, err := NewMLDSAPrivateCertificate(rootSubject, rootIssuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}

	interSubject := pkix.Name{CommonName: "Intermediate CA"}
	interIssuer := rootSubject

	interPrivCert, err := NewMLDSAPrivateCertificate(interSubject, interIssuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}

	interPubCert, err := NewMLDSAPublicCertificateFromPublicKey(
		interSubject, interIssuer, notBefore, notAfter,
		interPrivCert.PublicCert().GetPublicKey(), rootPrivCert.PrivateKey,
	)
	if err != nil {
		t.Fatalf("Failed to create intermediate cert: %v", err)
	}

	chain := []*MLDSAPublicCertificate{interPubCert, rootPrivCert.PublicCert()}

	// Valid chain
	err = VerifyChain(chain)
	if err != nil {
		t.Fatalf("Valid chain verification failed: %v", err)
	}

	// Invalid chain (wrong order)
	invalidChain := []*MLDSAPublicCertificate{rootPrivCert.PublicCert(), interPubCert}
	err = VerifyChain(invalidChain)
	if err == nil {
		t.Fatal("Invalid chain should fail verification")
	}

	// Empty chain
	err = VerifyChain([]*MLDSAPublicCertificate{})
	if err == nil {
		t.Fatal("Empty chain should fail verification")
	}
}

func Example() {
	// Root CA 생성
	rootSubject := pkix.Name{CommonName: "Root CA", Organization: []string{"Example Corp"}}
	rootIssuer := pkix.Name{CommonName: "Root CA", Organization: []string{"Example Corp"}}
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	rootPrivCert, err := NewMLDSAPrivateCertificate(rootSubject, rootIssuer, notBefore, notAfter)
	if err != nil {
		panic(err)
	}
	rootPubCert := rootPrivCert.PublicCert()
	rootPubKey := rootPubCert.GetPublicKey()

	// Root CA 검증 (self-verification)
	err = rootPubCert.Verify()
	if err != nil {
		panic("Root CA verification failed")
	}

	// Intermediate CA 생성 (Root CA로 서명)
	interSubject := pkix.Name{CommonName: "Intermediate CA", Organization: []string{"Example Corp"}}
	interIssuer := rootSubject // Issuer는 Root CA

	interPrivCert, err := NewMLDSAPrivateCertificate(interSubject, interIssuer, notBefore, notAfter)
	if err != nil {
		panic(err)
	}
	interPubCert, err := NewMLDSAPublicCertificateFromPublicKey(
		interSubject, interIssuer, notBefore, notAfter,
		interPrivCert.PublicCert().GetPublicKey(), rootPrivCert.PrivateKey,
	)
	if err != nil {
		panic(err)
	}

	// Intermediate CA 검증 (Root CA의 공개키로)
	err = interPubCert.VerifyWithKey(rootPubKey)
	if err != nil {
		panic("Intermediate CA verification failed")
	}

	// Personal Certificate 생성 (Intermediate CA로 서명)
	personalSubject := pkix.Name{CommonName: "user@example.com", Organization: []string{"Example Corp"}}
	personalIssuer := interSubject // Issuer는 Intermediate CA

	personalPrivCert, err := NewMLDSAPrivateCertificate(personalSubject, personalIssuer, notBefore, notAfter)
	if err != nil {
		panic(err)
	}
	personalPubCert, err := NewMLDSAPublicCertificateFromPublicKey(
		personalSubject, personalIssuer, notBefore, notAfter,
		personalPrivCert.PublicCert().GetPublicKey(), interPrivCert.PrivateKey,
	)
	if err != nil {
		panic(err)
	}

	// Personal Certificate 검증 (Intermediate CA의 공개키로)
	interPubKey := interPubCert.GetPublicKey()
	err = personalPubCert.VerifyWithKey(interPubKey)
	if err != nil {
		panic("Personal certificate verification failed")
	}

	// 데이터 서명 및 검증 예시
	data := []byte("Hello, secure world!")
	signature, err := personalPrivCert.SignData(data)
	if err != nil {
		panic("Signing failed")
	}

	valid := personalPubCert.VerifyData(data, signature)
	if !valid {
		panic("Verification failed")
	}

	// Certificate Chain 생성 및 검증 예시
	// 체인: Personal -> Intermediate -> Root
	rootPEM, _ := rootPubCert.MarshalPEM()
	interPEM, _ := interPubCert.MarshalPEM()
	personalPEM, _ := personalPubCert.MarshalPEM()

	chainPEM := append(personalPEM, append(interPEM, rootPEM...)...)

	// 체인 파싱
	chain, err := ParseCertificateChain(chainPEM)
	if err != nil {
		panic("Chain parsing failed")
	}

	// 체인 검증
	err = VerifyChain(chain)
	if err != nil {
		panic("Chain verification failed")
	}

	fmt.Println("Certificate chain created, parsed, and verified successfully")
	// Output: Certificate chain created, parsed, and verified successfully
}

func TestTrustStore(t *testing.T) {
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	// Create root CA
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootCert, err := NewMLDSAPrivateCertificate(rootSubject, rootSubject, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	// Create trust store and add root CA
	ts := NewTrustStore()
	err = ts.AddRootCA(rootCert.PublicCert())
	if err != nil {
		t.Fatalf("Failed to add root CA: %v", err)
	}

	// Verify root CA is in store
	rootCAs := ts.GetRootCAs()
	if len(rootCAs) != 1 {
		t.Fatalf("Expected 1 root CA, got %d", len(rootCAs))
	}

	// Try to add duplicate
	err = ts.AddRootCA(rootCert.PublicCert())
	if err == nil {
		t.Fatal("Expected error when adding duplicate root CA")
	}

	// Remove root CA
	removed := ts.RemoveRootCA(rootSubject, rootCert.PublicCert().TBS.SerialNumber)
	if !removed {
		t.Fatal("Failed to remove root CA")
	}

	// Verify store is empty
	rootCAs = ts.GetRootCAs()
	if len(rootCAs) != 0 {
		t.Fatalf("Expected 0 root CAs, got %d", len(rootCAs))
	}
}

func TestTrustStoreSaveLoad(t *testing.T) {
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	// Create multiple root CAs
	ts := NewTrustStore()

	for i := 1; i <= 3; i++ {
		subject := pkix.Name{CommonName: fmt.Sprintf("Root CA %d", i)}
		cert, err := NewMLDSAPrivateCertificate(subject, subject, notBefore, notAfter)
		if err != nil {
			t.Fatalf("Failed to create root certificate %d: %v", i, err)
		}
		err = ts.AddRootCA(cert.PublicCert())
		if err != nil {
			t.Fatalf("Failed to add root CA %d: %v", i, err)
		}
	}

	// Save to file
	filename := "test_truststore.pem"
	defer os.Remove(filename)

	err := ts.SaveToFile(filename)
	if err != nil {
		t.Fatalf("Failed to save trust store: %v", err)
	}

	// Load from file
	ts2 := NewTrustStore()
	err = ts2.LoadFromFile(filename)
	if err != nil {
		t.Fatalf("Failed to load trust store: %v", err)
	}

	// Verify loaded trust store
	rootCAs := ts2.GetRootCAs()
	if len(rootCAs) != 3 {
		t.Fatalf("Expected 3 root CAs, got %d", len(rootCAs))
	}
}

func TestVerifyWithTrustStore(t *testing.T) {
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	// Create root CA
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootCert, err := NewMLDSAPrivateCertificate(rootSubject, rootSubject, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	// Create intermediate CA signed by root
	interSubject := pkix.Name{CommonName: "Intermediate CA"}
	interPrivCert, err := NewMLDSAPrivateCertificate(interSubject, rootSubject, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create intermediate private certificate: %v", err)
	}

	interCert, err := NewMLDSAPublicCertificateFromPublicKey(
		interSubject,
		rootSubject,
		notBefore,
		notAfter,
		interPrivCert.PublicCert().GetPublicKey(),
		rootCert.PrivateKey,
	)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	} // Create trust store with root CA
	ts := NewTrustStore()
	err = ts.AddRootCA(rootCert.PublicCert())
	if err != nil {
		t.Fatalf("Failed to add root CA: %v", err)
	}

	// Verify chain with trust store
	chain := []*MLDSAPublicCertificate{interCert}
	err = ts.VerifyWithTrustStore(chain)
	if err != nil {
		t.Fatalf("Failed to verify with trust store: %v", err)
	}

	// Test with untrusted chain
	untrustedRoot := pkix.Name{CommonName: "Untrusted Root"}
	untrustedCert, _ := NewMLDSAPrivateCertificate(untrustedRoot, untrustedRoot, notBefore, notAfter)
	untrustedChain := []*MLDSAPublicCertificate{untrustedCert.PublicCert()}

	err = ts.VerifyWithTrustStore(untrustedChain)
	if err == nil {
		t.Fatal("Expected error when verifying untrusted chain")
	}
}

func ExampleTrustStore() {
	// Create a trust store
	ts := NewTrustStore()

	// Create root CA certificates
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	rootSubject := pkix.Name{CommonName: "My Root CA"}
	rootCert, _ := NewMLDSAPrivateCertificate(rootSubject, rootSubject, notBefore, notAfter)

	// Add root CA to trust store
	ts.AddRootCA(rootCert.PublicCert())

	// Create intermediate certificate signed by root CA
	interSubject := pkix.Name{CommonName: "Intermediate CA"}
	interCert, _ := NewMLDSAPublicCertificateFromPublicKey(
		interSubject,
		rootSubject,
		notBefore,
		notAfter,
		nil,
		rootCert.PrivateKey,
	)

	// Verify certificate chain against trust store
	chain := []*MLDSAPublicCertificate{interCert}
	err := ts.VerifyWithTrustStore(chain)
	if err != nil {
		fmt.Println("Verification failed")
	} else {
		fmt.Println("Certificate chain verified successfully")
	}

	// Save trust store to file
	// ts.SaveToFile("truststore.pem")

	// Load trust store from file
	// ts2 := NewTrustStore()
	// ts2.LoadFromFile("truststore.pem")

	// Get all root CAs
	rootCAs := ts.GetRootCAs()
	fmt.Printf("Trust store contains %d root CA(s)\n", len(rootCAs))

	// Output:
	// Certificate chain verified successfully
	// Trust store contains 1 root CA(s)
}
