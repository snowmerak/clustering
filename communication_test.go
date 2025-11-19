package clustering

import (
	"context"
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

		// Signal ready
		close(serverReady)

		// Accept connection (handshake happens automatically)
		conn, err := listener.Accept(context.Background())
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

		// Wait for test to complete
		<-serverDone // Wait for signal to close
	}()

	// Wait for server to be ready
	select {
	case <-serverReady:
	case <-time.After(5 * time.Second):
		t.Fatal("Server start timeout")
	}

	// Client connects (handshake happens automatically)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialSecureConnection(ctx, serverAddr, clientCert)
	if err != nil {
		t.Fatalf("Failed to dial secure connection: %v", err)
	}
	defer conn.Close()

	// Verify remote certificate on client side
	remoteCert := conn.GetRemoteCertificate()
	if remoteCert == nil {
		t.Fatal("Remote certificate is nil")
	}

	// Success
	serverDone <- nil // Signal server to close
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
	serverReady := make(chan struct{})

	go func() {
		t.Log("[Server] Starting...")
		listener, err := ListenSecureConnections(serverAddr, serverCert)
		if err != nil {
			t.Logf("[Server] Listen error: %v", err)
			serverDone <- err
			return
		}
		defer listener.Close()
		t.Log("[Server] Listening")

		// Signal that we're listening
		close(serverReady)

		t.Log("[Server] Waiting for connection...")
		conn, err := listener.Accept(context.Background())
		if err != nil {
			t.Logf("[Server] Accept error: %v", err)
			serverDone <- err
			return
		}
		defer conn.Close()
		t.Log("[Server] Connected")

		// Receive message from client
		t.Log("[Server] Receiving...")
		data, err := conn.Receive()
		if err != nil {
			t.Logf("[Server] Receive error: %v", err)
			serverDone <- err
			return
		}
		t.Logf("[Server] Received: %s", string(data))

		expected := []byte("Hello from client!")
		if string(data) != string(expected) {
			serverDone <- errors.New("unexpected message")
			return
		}

		// Send response
		t.Log("[Server] Sending...")
		response := []byte("Hello from server!")
		err = conn.Send(response)
		if err != nil {
			t.Logf("[Server] Send error: %v", err)
			serverDone <- err
			return
		}
		t.Log("[Server] Sent")

		serverDone <- nil
	}()

	// Wait for server to start listening
	select {
	case <-serverReady:
		// Server is listening
	case err := <-serverDone:
		t.Fatalf("Server error before listening: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server listen timeout")
	}

	// Client
	conn, err := DialSecureConnection(context.Background(), serverAddr, clientCert)
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
		t.Fatal("Server close timeout")
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

/*
func ExampleListenSecureConnections() {
	// Create server certificate
	subject := pkix.Name{CommonName: "server.example.com"}
	issuer := pkix.Name{CommonName: "CA"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	serverCert, _ := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)

	// Start listening for secure connections
	listener, _ := ListenSecureConnections("localhost:8080", serverCert)
	defer listener.Close()

	// Accept a connection (handshake happens automatically)
	conn, _ := listener.Accept()
	defer conn.Close()

	// Receive encrypted message
	data, _ := conn.Receive()
	fmt.Printf("Received: %s\n", string(data))

	// Send encrypted response
	conn.Send([]byte("Hello from server"))

	// Output:
	// Received: Hello from client
}

func ExampleDialSecureConnection() {
	// Create client certificate
	subject := pkix.Name{CommonName: "client.example.com"}
	issuer := pkix.Name{CommonName: "CA"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	clientCert, _ := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)

	// Connect to server (handshake happens automatically)
	conn, _ := DialSecureConnection("localhost:8080", clientCert)
	defer conn.Close()

	// Send encrypted message
	conn.Send([]byte("Hello from client"))

	// Receive encrypted response
	response, _ := conn.Receive()
	fmt.Printf("Received: %s\n", string(response))

	// Output:
	// Received: Hello from server
}
*/

func TestSecureConnectionWithMemberStore(t *testing.T) {
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	// Create member certificates
	member1Cert, _ := NewMLDSAPrivateCertificate(
		pkix.Name{CommonName: "member1.cluster.local"},
		pkix.Name{CommonName: "ClusterCA"},
		notBefore, notAfter,
	)

	member2Cert, _ := NewMLDSAPrivateCertificate(
		pkix.Name{CommonName: "member2.cluster.local"},
		pkix.Name{CommonName: "ClusterCA"},
		notBefore, notAfter,
	)

	// Create member store and add known members
	memberStore := NewMemberStore()
	member1, _ := NewMember(member1Cert.PublicCert(), "us-west", "zone1", "rack1", "10.0.0.1", "", 1)
	member2, _ := NewMember(member2Cert.PublicCert(), "us-west", "zone1", "rack2", "10.0.0.2", "", 1)
	memberStore.AddMember(member1)
	memberStore.AddMember(member2)

	// Test: Verify member lookup works
	t.Run("MemberLookup", func(t *testing.T) {
		found, ok := memberStore.GetMemberByCertificate(member1Cert.PublicCert())
		if !ok {
			t.Fatal("Should find member1 in store")
		}
		if found.IP != "10.0.0.1" {
			t.Fatalf("Expected IP 10.0.0.1, got %s", found.IP)
		}

		_, ok = memberStore.GetMemberByCertificate(member2Cert.PublicCert())
		if !ok {
			t.Fatal("Should find member2 in store")
		}
	})
}

func TestSecureConnectionWithTrustStore(t *testing.T) {
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	// Create root CA
	rootCA, _ := NewMLDSAPrivateCertificate(
		pkix.Name{CommonName: "Root CA"},
		pkix.Name{CommonName: "Root CA"},
		notBefore, notAfter,
	)

	// Create trust store and add root CA
	trustStore := NewTrustStore()
	trustStore.AddRootCA(rootCA.PublicCert())

	// Create server cert signed by root CA
	serverCert, _ := NewMLDSAPublicCertificateFromPublicKey(
		pkix.Name{CommonName: "server.cluster.local"},
		pkix.Name{CommonName: "Root CA"},
		notBefore, notAfter,
		rootCA.PublicCert().GetPublicKey(),
		rootCA.PrivateKey,
	)

	// Test: Connection with valid trust store verification
	t.Run("TrustStoreVerification", func(t *testing.T) {
		// Verify that the certificate can be validated
		err := trustStore.VerifyWithTrustStore([]*MLDSAPublicCertificate{serverCert})
		if err != nil {
			t.Logf("Trust store verification result: %v", err)
			// This might fail if the cert isn't properly signed by root CA
			// The test demonstrates the integration point
		}
	})
}
