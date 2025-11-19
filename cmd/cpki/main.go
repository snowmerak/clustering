package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/snowmerak/clustering"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "root":
		handleRoot(os.Args[2:])
	case "intermediate":
		handleIntermediate(os.Args[2:])
	case "leaf":
		handleLeaf(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: cpki <command> [options]")
	fmt.Println("Commands:")
	fmt.Println("  root          Generate a Root CA certificate")
	fmt.Println("  intermediate  Generate an Intermediate CA certificate")
	fmt.Println("  leaf          Generate a Leaf certificate")
}

func handleRoot(args []string) {
	cmd := flag.NewFlagSet("root", flag.ExitOnError)
	outCert := cmd.String("out-cert", "root.crt", "Output certificate file")
	outKey := cmd.String("out-key", "root.key", "Output private key file")
	cn := cmd.String("cn", "Root CA", "Common Name")
	org := cmd.String("org", "My Org", "Organization")
	days := cmd.Int("days", 3650, "Validity in days")

	cmd.Parse(args)

	subject := pkix.Name{
		CommonName:   *cn,
		Organization: []string{*org},
	}
	// Root CA is self-signed, so Issuer = Subject
	issuer := subject

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(*days) * 24 * time.Hour)

	fmt.Printf("Generating Root CA: %s\n", *cn)
	cert, err := clustering.NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)
	if err != nil {
		fail("Failed to generate root certificate: %v", err)
	}

	saveCertAndKey(cert, *outCert, *outKey)
}

func handleIntermediate(args []string) {
	cmd := flag.NewFlagSet("intermediate", flag.ExitOnError)
	caCertPath := cmd.String("ca-cert", "root.crt", "CA certificate file")
	caKeyPath := cmd.String("ca-key", "root.key", "CA private key file")
	outCert := cmd.String("out-cert", "intermediate.crt", "Output certificate file")
	outKey := cmd.String("out-key", "intermediate.key", "Output private key file")
	cn := cmd.String("cn", "Intermediate CA", "Common Name")
	org := cmd.String("org", "My Org", "Organization")
	days := cmd.Int("days", 1825, "Validity in days")

	cmd.Parse(args)

	generateSignedCert(*caCertPath, *caKeyPath, *outCert, *outKey, *cn, *org, *days)
}

func handleLeaf(args []string) {
	cmd := flag.NewFlagSet("leaf", flag.ExitOnError)
	caCertPath := cmd.String("ca-cert", "intermediate.crt", "CA certificate file")
	caKeyPath := cmd.String("ca-key", "intermediate.key", "CA private key file")
	outCert := cmd.String("out-cert", "leaf.crt", "Output certificate file")
	outKey := cmd.String("out-key", "leaf.key", "Output private key file")
	cn := cmd.String("cn", "Leaf Cert", "Common Name")
	org := cmd.String("org", "My Org", "Organization")
	days := cmd.Int("days", 365, "Validity in days")
	ips := cmd.String("ips", "", "Comma-separated IP addresses (optional)")
	domains := cmd.String("domains", "", "Comma-separated domains (optional)")

	cmd.Parse(args)

	// Note: The current MLDSATBS struct in x509.go does not support SANs (IPs/Domains) explicitly in the struct fields.
	// It only has Subject/Issuer/etc.
	// If we want to support SANs, we would need to extend MLDSATBS.
	// For now, we will just use CN/Org.
	if *ips != "" || *domains != "" {
		fmt.Println("Warning: IP/Domain SANs are not yet supported in the certificate structure. Ignoring.")
	}

	generateSignedCert(*caCertPath, *caKeyPath, *outCert, *outKey, *cn, *org, *days)
}

func generateSignedCert(caCertPath, caKeyPath, outCert, outKey, cn, org string, days int) {
	// Load CA Cert
	caCertBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		fail("Failed to read CA cert: %v", err)
	}
	caCert, err := clustering.UnmarshalPEM(caCertBytes)
	if err != nil {
		fail("Failed to parse CA cert: %v", err)
	}

	// Load CA Key
	caKeyBytes, err := os.ReadFile(caKeyPath)
	if err != nil {
		fail("Failed to read CA key: %v", err)
	}
	caKey, err := clustering.UnmarshalPrivateKeyPEM(caKeyBytes)
	if err != nil {
		fail("Failed to parse CA key: %v", err)
	}

	// Generate new key pair
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		fail("Failed to generate key pair: %v", err)
	}

	subject := pkix.Name{
		CommonName:   cn,
		Organization: []string{org},
	}
	issuer := caCert.TBS.Subject

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)

	fmt.Printf("Generating Certificate: %s (Signed by %s)\n", cn, issuer.CommonName)

	// Create signed certificate
	pubCert, err := clustering.NewMLDSAPublicCertificateFromPublicKey(subject, issuer, notBefore, notAfter, pub, caKey)
	if err != nil {
		fail("Failed to create certificate: %v", err)
	}

	// Combine into PrivateCertificate for saving
	privCert := &clustering.MLDSAPrivateCertificate{
		PublicCertificate: *pubCert,
		PrivateKey:        priv,
	}

	saveCertAndKey(privCert, outCert, outKey)
}

func saveCertAndKey(cert *clustering.MLDSAPrivateCertificate, certPath, keyPath string) {
	// Save Cert
	certPEM, err := cert.PublicCert().MarshalPEM()
	if err != nil {
		fail("Failed to marshal cert: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		fail("Failed to write cert file: %v", err)
	}
	fmt.Printf("Wrote certificate to %s\n", certPath)

	// Save Key
	keyPEM, err := cert.MarshalPrivateKeyPEM()
	if err != nil {
		fail("Failed to marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		fail("Failed to write key file: %v", err)
	}
	fmt.Printf("Wrote private key to %s\n", keyPath)
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
