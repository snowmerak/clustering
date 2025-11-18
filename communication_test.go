package clustering

import (
	"crypto/mlkem"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"
)

func TestSecureConnectionHandshake(t *testing.T) {
	// Create server certificate
	serverSubject := pkix.Name{CommonName: "server.example.com"}
	serverIssuer := pkix.Name{CommonName: "CA"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	serverCert, err := NewMLDSAPrivateCertificate(serverSubject, serverIssuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Create client certificate
	clientSubject := pkix.Name{CommonName: "client.example.com"}
	clientIssuer := pkix.Name{CommonName: "CA"}

	clientCert, err := NewMLDSAPrivateCertificate(clientSubject, clientIssuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	serverAddr := "localhost:12345"

	// Start server in goroutine
	serverDone := make(chan error, 1)
	serverReady := make(chan struct{})
	go func() {
		listener, err := ListenSecureConnections(serverAddr, serverCert)
		if err != nil {
			serverDone <- err
			return
		}
		defer listener.Close()

		// Accept connection (handshake happens automatically)
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		// Verify remote certificate
		remoteCert := conn.GetRemoteCertificate()
		if remoteCert == nil {
			serverDone <- errors.New("remote certificate is nil")
			return
		}

		// Signal ready and wait for test to complete
		close(serverReady)
		<-serverDone // Wait for signal to close
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Client connects (handshake happens automatically)
	conn, err := DialSecureConnection(serverAddr, clientCert)
	if err != nil {
		t.Fatalf("Failed to dial secure connection: %v", err)
	}
	defer conn.Close()

	// Verify remote certificate on client side
	remoteCert := conn.GetRemoteCertificate()
	if remoteCert == nil {
		t.Fatal("Remote certificate is nil")
	}

	// Wait for server to be ready
	select {
	case <-serverReady:
		// Success
		serverDone <- nil // Signal server to close
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("Server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Server timeout")
	}
}

func TestSecureConnectionSendReceive(t *testing.T) {
	// Create certificates
	serverSubject := pkix.Name{CommonName: "server.example.com"}
	serverIssuer := pkix.Name{CommonName: "CA"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	serverCert, err := NewMLDSAPrivateCertificate(serverSubject, serverIssuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	clientSubject := pkix.Name{CommonName: "client.example.com"}
	clientIssuer := pkix.Name{CommonName: "CA"}

	clientCert, err := NewMLDSAPrivateCertificate(clientSubject, clientIssuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	serverAddr := "localhost:12346"

	// Start server
	serverDone := make(chan error, 1)
	go func() {
		listener, err := ListenSecureConnections(serverAddr, serverCert)
		if err != nil {
			serverDone <- err
			return
		}
		defer listener.Close()

		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		// Receive message from client
		data, err := conn.Receive()
		if err != nil {
			serverDone <- err
			return
		}

		expected := []byte("Hello from client!")
		if string(data) != string(expected) {
			serverDone <- err
			return
		}

		// Send response
		response := []byte("Hello from server!")
		err = conn.Send(response)
		if err != nil {
			serverDone <- err
			return
		}

		serverDone <- nil
	}()

	time.Sleep(100 * time.Millisecond)

	// Client
	conn, err := DialSecureConnection(serverAddr, clientCert)
	if err != nil {
		t.Fatalf("Failed to dial secure connection: %v", err)
	}
	defer conn.Close()

	// Send message to server
	message := []byte("Hello from client!")
	err = conn.Send(message)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Receive response from server
	response, err := conn.Receive()
	if err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	expectedResponse := []byte("Hello from server!")
	if string(response) != string(expectedResponse) {
		t.Fatalf("Unexpected response: got %s, want %s", string(response), string(expectedResponse))
	}

	// Wait for server
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("Server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Server timeout")
	}
}

func TestMLKEMKeyExchange(t *testing.T) {
	// Test ML-KEM key exchange primitives
	privKey, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey := privKey.EncapsulationKey()

	// Test encapsulation/decapsulation
	sharedSecret1, ciphertext := pubKey.Encapsulate()
	sharedSecret2, err := privKey.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decapsulate: %v", err)
	}

	if string(sharedSecret1) != string(sharedSecret2) {
		t.Fatal("Shared secrets don't match")
	}
}

func TestCertificateVerification(t *testing.T) {
	// Create a certificate
	subject := pkix.Name{CommonName: "test.example.com"}
	issuer := pkix.Name{CommonName: "CA"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	privCert, err := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	pubCert := privCert.PublicCert()

	// Test self-verification
	err = pubCert.Verify()
	if err != nil {
		t.Fatalf("Certificate verification failed: %v", err)
	}

	// Test signing and verification
	testData := []byte("test data")
	sig, err := privCert.SignData(testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	valid := pubCert.VerifyData(testData, sig)
	if !valid {
		t.Fatal("Signature verification failed")
	}
}
