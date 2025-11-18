package clustering

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// MLDSAPublicCertificate represents a public X.509-like certificate using ML-DSA (Dilithium) for signatures.
// It contains only the public key and is suitable for distribution and verification.
type MLDSAPublicCertificate struct {
	TBS       MLDSATBS
	Signature []byte
}

// MLDSAPrivateCertificate represents a private X.509-like certificate using ML-DSA (Dilithium) for signatures.
// It contains both the public certificate and the private key for signing.
type MLDSAPrivateCertificate struct {
	PublicCertificate MLDSAPublicCertificate
	PrivateKey        *mldsa87.PrivateKey
}

// MLDSATBS represents the To-Be-Signed portion of the certificate.
type MLDSATBS struct {
	Version      int `asn1:"tag:0,optional"`
	SerialNumber *big.Int
	Subject      pkix.Name
	Issuer       pkix.Name
	NotBefore    time.Time
	NotAfter     time.Time
	PublicKey    asn1.RawValue `asn1:"tag:3"`
}

// NewMLDSAPublicCertificateFromPublicKey creates a new public ML-DSA certificate using the provided public key and signs it with the provided private key.
// This is useful for creating certificates for distribution where the public key is already known.
func NewMLDSAPublicCertificateFromPublicKey(subject, issuer pkix.Name, notBefore, notAfter time.Time, pub *mldsa87.PublicKey, signerPriv *mldsa87.PrivateKey) (*MLDSAPublicCertificate, error) {
	var pubBytes [mldsa87.PublicKeySize]byte
	pub.Pack(&pubBytes)

	tbs := MLDSATBS{
		Version:      0,
		SerialNumber: big.NewInt(1), // In production, use a random serial number
		Subject:      subject,
		Issuer:       issuer,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey: asn1.RawValue{
			Tag:   3,
			Class: asn1.ClassContextSpecific,
			Bytes: pubBytes[:],
		},
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}

	sig := make([]byte, mldsa87.SignatureSize)
	err = mldsa87.SignTo(signerPriv, tbsBytes, []byte{}, false, sig)
	if err != nil {
		return nil, err
	}

	cert := &MLDSAPublicCertificate{
		TBS:       tbs,
		Signature: sig,
	}

	return cert, nil
}

// NewMLDSAPrivateCertificate creates a new private ML-DSA certificate with the given parameters.
// It generates a new key pair and signs the certificate.
func NewMLDSAPrivateCertificate(subject, issuer pkix.Name, notBefore, notAfter time.Time) (*MLDSAPrivateCertificate, error) {
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var pubBytes [mldsa87.PublicKeySize]byte
	pub.Pack(&pubBytes)

	tbs := MLDSATBS{
		Version:      0,
		SerialNumber: big.NewInt(1), // In production, use a random serial number
		Subject:      subject,
		Issuer:       issuer,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey: asn1.RawValue{
			Tag:   3,
			Class: asn1.ClassContextSpecific,
			Bytes: pubBytes[:],
		},
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}

	sig := make([]byte, mldsa87.SignatureSize)
	err = mldsa87.SignTo(priv, tbsBytes, []byte{}, false, sig)
	if err != nil {
		return nil, err
	}

	publicCert := MLDSAPublicCertificate{
		TBS:       tbs,
		Signature: sig,
	}

	privateCert := &MLDSAPrivateCertificate{
		PublicCertificate: publicCert,
		PrivateKey:        priv,
	}

	return privateCert, nil
}

// MarshalPEM marshals the certificate to PEM format.
func (c *MLDSAPublicCertificate) MarshalPEM() ([]byte, error) {
	certBytes, err := asn1.Marshal(*c)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "MLDSA CERTIFICATE",
		Bytes: certBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// UnmarshalPEM unmarshals a certificate from PEM format.
func UnmarshalPEM(data []byte) (*MLDSAPublicCertificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "MLDSA CERTIFICATE" {
		return nil, errors.New("invalid PEM block")
	}

	var cert MLDSAPublicCertificate
	_, err := asn1.Unmarshal(block.Bytes, &cert)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// Verify checks the signature of the certificate.
func (c *MLDSAPublicCertificate) Verify() error {
	tbsBytes, err := asn1.Marshal(c.TBS)
	if err != nil {
		return err
	}

	var pub mldsa87.PublicKey
	var pubBytes [mldsa87.PublicKeySize]byte
	copy(pubBytes[:], c.TBS.PublicKey.Bytes)
	pub.Unpack(&pubBytes)

	if !mldsa87.Verify(&pub, tbsBytes, []byte{}, c.Signature) {
		return errors.New("signature verification failed")
	}

	return nil
}

// GetPublicKey returns the ML-DSA public key from the certificate.
func (c *MLDSAPublicCertificate) GetPublicKey() *mldsa87.PublicKey {
	var pub mldsa87.PublicKey
	var pubBytes [mldsa87.PublicKeySize]byte
	copy(pubBytes[:], c.TBS.PublicKey.Bytes)
	pub.Unpack(&pubBytes)
	return &pub
}

// VerifyData verifies the signature of the given data using the certificate's public key.
func (c *MLDSAPublicCertificate) VerifyData(data []byte, sig []byte) bool {
	pub := c.GetPublicKey()
	return mldsa87.Verify(pub, data, []byte{}, sig)
}

// VerifyWithKey verifies the certificate's signature using the provided public key (e.g., parent CA's key).
func (c *MLDSAPublicCertificate) VerifyWithKey(signerPub *mldsa87.PublicKey) error {
	tbsBytes, err := asn1.Marshal(c.TBS)
	if err != nil {
		return err
	}

	if !mldsa87.Verify(signerPub, tbsBytes, []byte{}, c.Signature) {
		return errors.New("signature verification failed")
	}

	return nil
}

// ParseCertificateChain parses multiple certificates from PEM data.
func ParseCertificateChain(pemData []byte) ([]*MLDSAPublicCertificate, error) {
	var certs []*MLDSAPublicCertificate

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "MLDSA CERTIFICATE" {
			pemData = rest
			continue
		}

		cert, err := UnmarshalPEM(pem.EncodeToMemory(block))
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal certificate: %w", err)
		}

		certs = append(certs, cert)
		pemData = rest
	}

	return certs, nil
}

// VerifyChain verifies the certificate chain.
func VerifyChain(chain []*MLDSAPublicCertificate) error {
	if len(chain) == 0 {
		return errors.New("empty chain")
	}

	// Root certificate (last in chain) should be self-verifying
	root := chain[len(chain)-1]
	if err := root.Verify(); err != nil {
		return fmt.Errorf("root certificate verification failed: %w", err)
	}

	// Verify each certificate with the next one
	for i := 0; i < len(chain)-1; i++ {
		current := chain[i]
		issuer := chain[i+1]

		issuerPubKey := issuer.GetPublicKey()
		if err := current.VerifyWithKey(issuerPubKey); err != nil {
			return fmt.Errorf("certificate %d verification failed: %w", i, err)
		}
	}

	return nil
}

// TrustStore manages a collection of trusted root CA certificates.
type TrustStore struct {
	RootCAs []*MLDSAPublicCertificate
}

// NewTrustStore creates a new empty trust store.
func NewTrustStore() *TrustStore {
	return &TrustStore{
		RootCAs: make([]*MLDSAPublicCertificate, 0),
	}
}

// AddRootCA adds a root CA certificate to the trust store.
func (ts *TrustStore) AddRootCA(cert *MLDSAPublicCertificate) error {
	// Verify it's a valid self-signed certificate
	if err := cert.Verify(); err != nil {
		return fmt.Errorf("invalid root CA certificate: %w", err)
	}

	// Check if already exists
	for _, existing := range ts.RootCAs {
		if existing.TBS.Subject.String() == cert.TBS.Subject.String() &&
			existing.TBS.SerialNumber.Cmp(cert.TBS.SerialNumber) == 0 {
			return errors.New("root CA already exists in trust store")
		}
	}

	ts.RootCAs = append(ts.RootCAs, cert)
	return nil
}

// RemoveRootCA removes a root CA certificate from the trust store by subject and serial number.
func (ts *TrustStore) RemoveRootCA(subject pkix.Name, serialNumber *big.Int) bool {
	for i, cert := range ts.RootCAs {
		if cert.TBS.Subject.String() == subject.String() &&
			cert.TBS.SerialNumber.Cmp(serialNumber) == 0 {
			ts.RootCAs = append(ts.RootCAs[:i], ts.RootCAs[i+1:]...)
			return true
		}
	}
	return false
}

// VerifyWithTrustStore verifies a certificate chain against the trust store.
// The chain should start with the end entity certificate and end with an intermediate CA.
// The function will try to find a matching root CA in the trust store.
func (ts *TrustStore) VerifyWithTrustStore(chain []*MLDSAPublicCertificate) error {
	if len(chain) == 0 {
		return errors.New("empty certificate chain")
	}

	// Find the issuer of the last certificate in the chain
	lastCert := chain[len(chain)-1]
	issuerName := lastCert.TBS.Issuer.String()

	var rootCA *MLDSAPublicCertificate
	for _, ca := range ts.RootCAs {
		if ca.TBS.Subject.String() == issuerName {
			rootCA = ca
			break
		}
	}

	if rootCA == nil {
		return errors.New("no trusted root CA found for certificate chain")
	}

	// Verify the last certificate with the root CA
	if err := lastCert.VerifyWithKey(rootCA.GetPublicKey()); err != nil {
		return fmt.Errorf("failed to verify with root CA: %w", err)
	}

	// Verify the rest of the chain
	for i := 0; i < len(chain)-1; i++ {
		current := chain[i]
		issuer := chain[i+1]

		if err := current.VerifyWithKey(issuer.GetPublicKey()); err != nil {
			return fmt.Errorf("certificate %d verification failed: %w", i, err)
		}
	}

	return nil
}

// SaveToFile saves all root CA certificates to a PEM file.
func (ts *TrustStore) SaveToFile(filename string) error {
	var pemData []byte

	for _, cert := range ts.RootCAs {
		certPEM, err := cert.MarshalPEM()
		if err != nil {
			return fmt.Errorf("failed to marshal certificate: %w", err)
		}
		pemData = append(pemData, certPEM...)
	}

	return os.WriteFile(filename, pemData, 0644)
}

// LoadFromFile loads root CA certificates from a PEM file.
func (ts *TrustStore) LoadFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	certs, err := ParseCertificateChain(data)
	if err != nil {
		return fmt.Errorf("failed to parse certificate chain: %w", err)
	}

	// Verify and add each certificate
	for _, cert := range certs {
		if err := ts.AddRootCA(cert); err != nil {
			return fmt.Errorf("failed to add root CA: %w", err)
		}
	}

	return nil
}

// GetRootCAs returns a copy of all root CA certificates.
func (ts *TrustStore) GetRootCAs() []*MLDSAPublicCertificate {
	certs := make([]*MLDSAPublicCertificate, len(ts.RootCAs))
	copy(certs, ts.RootCAs)
	return certs
}

// PublicCert returns the public certificate part of the private certificate.
func (c *MLDSAPrivateCertificate) PublicCert() *MLDSAPublicCertificate {
	return &c.PublicCertificate
}

// SignData signs the given data using the private key in the certificate.
func (c *MLDSAPrivateCertificate) SignData(data []byte) ([]byte, error) {
	sig := make([]byte, mldsa87.SignatureSize)
	err := mldsa87.SignTo(c.PrivateKey, data, []byte{}, false, sig)
	if err != nil {
		return nil, err
	}
	return sig, nil
}
