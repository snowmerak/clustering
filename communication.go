package clustering

import (
	"context"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

// SecureConnection represents a secure connection using KCP with ML-DSA certificates and ML-KEM key exchange
type SecureConnection struct {
	conn        *kcp.UDPSession
	localCert   *MLDSAPrivateCertificate
	remoteCert  *MLDSAPublicCertificate
	sharedKey   []byte
	aead        cipher.AEAD
	isServer    bool
	memberStore *MemberStore // Optional: if set, only accept connections from members
	trustStore  *TrustStore  // Optional: if set (and memberStore is nil), verify against trust store
	mu          sync.RWMutex
}

// NewSecureConnection creates a new secure connection with basic self-signed verification
func NewSecureConnection(conn *kcp.UDPSession, localCert *MLDSAPrivateCertificate, isServer bool) *SecureConnection {
	return &SecureConnection{
		conn:      conn,
		localCert: localCert,
		isServer:  isServer,
	}
}

// NewSecureConnectionWithMembers creates a secure connection that only accepts members from the store
func NewSecureConnectionWithMembers(conn *kcp.UDPSession, localCert *MLDSAPrivateCertificate, isServer bool, memberStore *MemberStore) *SecureConnection {
	return &SecureConnection{
		conn:        conn,
		localCert:   localCert,
		isServer:    isServer,
		memberStore: memberStore,
	}
}

// NewSecureConnectionWithTrustStore creates a secure connection that verifies against a trust store
func NewSecureConnectionWithTrustStore(conn *kcp.UDPSession, localCert *MLDSAPrivateCertificate, isServer bool, trustStore *TrustStore) *SecureConnection {
	return &SecureConnection{
		conn:       conn,
		localCert:  localCert,
		isServer:   isServer,
		trustStore: trustStore,
	}
}

// Handshake performs the certificate-based handshake and key exchange
func (sc *SecureConnection) Handshake(ctx context.Context) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if deadline, ok := ctx.Deadline(); ok {
		sc.conn.SetDeadline(deadline)
		defer sc.conn.SetDeadline(time.Time{})
	}

	if sc.isServer {
		return sc.serverHandshake(ctx)
	}
	return sc.clientHandshake(ctx)
}

// clientHandshake performs the client-side handshake
func (sc *SecureConnection) clientHandshake(ctx context.Context) error {
	// Send Hello message to initiate connection and wake up server's Accept
	helloMsg := []byte("Hello, I am in v1.0")
	if err := sc.sendMessage(helloMsg); err != nil {
		return fmt.Errorf("failed to send hello message: %w", err)
	}

	// Receive server certificate first
	serverCertPEM, err := sc.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive server certificate: %w", err)
	}

	serverCert, err := UnmarshalPEM(serverCertPEM)
	if err != nil {
		return fmt.Errorf("failed to unmarshal server certificate: %w", err)
	}

	// Verify server certificate using tiered authentication
	if err := sc.verifyCertificate(serverCert); err != nil {
		return fmt.Errorf("server certificate verification failed: %w", err)
	}

	sc.remoteCert = serverCert

	// Send local certificate
	certPEM, err := sc.localCert.PublicCert().MarshalPEM()
	if err != nil {
		return fmt.Errorf("failed to marshal certificate: %w", err)
	}

	if err := sc.sendMessage(certPEM); err != nil {
		return fmt.Errorf("failed to send certificate: %w", err)
	}

	// Perform ML-KEM key exchange
	if err := sc.performKeyExchange(); err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	return nil
}

// serverHandshake performs the server-side handshake
func (sc *SecureConnection) serverHandshake(ctx context.Context) error {
	// Receive Hello message
	helloMsg, err := sc.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive hello message: %w", err)
	}
	// TODO: Verify hello message version if needed
	_ = helloMsg

	// Send server certificate first
	certPEM, err := sc.localCert.PublicCert().MarshalPEM()
	if err != nil {
		return fmt.Errorf("failed to marshal certificate: %w", err)
	}

	if err := sc.sendMessage(certPEM); err != nil {
		return fmt.Errorf("failed to send certificate: %w", err)
	}

	// Receive client certificate
	clientCertPEM, err := sc.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive client certificate: %w", err)
	}

	clientCert, err := UnmarshalPEM(clientCertPEM)
	if err != nil {
		return fmt.Errorf("failed to unmarshal client certificate: %w", err)
	}

	// Verify client certificate using tiered authentication
	if err := sc.verifyCertificate(clientCert); err != nil {
		return fmt.Errorf("client certificate verification failed: %w", err)
	}

	sc.remoteCert = clientCert

	// Perform ML-KEM key exchange
	if err := sc.performKeyExchange(); err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	return nil
}

// verifyCertificate performs tiered certificate verification:
// 1. If memberStore is set, verify the certificate is from a known member
// 2. Else if trustStore is set, verify the certificate chain against trusted CAs
// 3. Else verify self-signed certificate only
func (sc *SecureConnection) verifyCertificate(cert *MLDSAPublicCertificate) error {
	// First priority: MemberStore - most restrictive
	if sc.memberStore != nil {
		_, found := sc.memberStore.GetMemberByCertificate(cert)
		if !found {
			return errors.New("certificate not found in member store")
		}
		// Still verify the certificate signature is valid
		if err := cert.Verify(); err != nil {
			return fmt.Errorf("member certificate signature invalid: %w", err)
		}
		return nil
	}

	// Second priority: TrustStore - verify against trusted CAs
	if sc.trustStore != nil {
		// For a single certificate, treat it as a chain of one
		// If it's self-signed, it should match a root CA
		// If it's not self-signed, we'd need the full chain
		if err := sc.trustStore.VerifyWithTrustStore([]*MLDSAPublicCertificate{cert}); err != nil {
			return fmt.Errorf("trust store verification failed: %w", err)
		}
		return nil
	}

	// Fallback: Basic self-signed verification
	if err := cert.Verify(); err != nil {
		return fmt.Errorf("self-signed verification failed: %w", err)
	}

	return nil
}

// performKeyExchange performs ML-KEM key encapsulation and decapsulation
func (sc *SecureConnection) performKeyExchange() error {
	if sc.isServer {
		return sc.serverKeyExchange()
	}
	return sc.clientKeyExchange()
}

// clientKeyExchange performs client-side key exchange
func (sc *SecureConnection) clientKeyExchange() error {
	// Receive server's ML-KEM public key
	pubKeyBytes, err := sc.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive server public key: %w", err)
	}

	pubKey, err := mlkem.NewEncapsulationKey1024(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse server public key: %w", err)
	}

	// Encapsulate shared secret using server's public key
	sharedSecret, ciphertext := pubKey.Encapsulate()

	// Send ciphertext to server
	if err := sc.sendMessage(ciphertext); err != nil {
		return fmt.Errorf("failed to send ciphertext: %w", err)
	}

	// Receive server's signature over the shared secret
	signature, err := sc.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive server signature: %w", err)
	}

	// Verify server's signature
	hash := blake3.New(32, nil)
	hash.Write(sharedSecret)
	digest := hash.Sum(nil)

	if !mldsa87.Verify(sc.remoteCert.GetPublicKey(), digest, []byte{}, signature) {
		return errors.New("server signature verification failed")
	}

	sc.sharedKey = sharedSecret
	if err := sc.deriveKeys(); err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	return nil
}

// serverKeyExchange performs server-side key exchange
func (sc *SecureConnection) serverKeyExchange() error {
	// Generate ML-KEM key pair
	decapsKey, err := mlkem.GenerateKey1024()
	if err != nil {
		return fmt.Errorf("failed to generate ML-KEM key pair: %w", err)
	}

	encapKey := decapsKey.EncapsulationKey()

	// Send encapsulation key (public key) to client
	if err := sc.sendMessage(encapKey.Bytes()); err != nil {
		return fmt.Errorf("failed to send public key: %w", err)
	}

	// Receive ciphertext from client
	ciphertext, err := sc.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive ciphertext: %w", err)
	}

	// Decapsulate shared secret using private key
	sharedSecret, err := decapsKey.Decapsulate(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decapsulate shared secret: %w", err)
	}

	// Sign the shared secret hash
	hash := blake3.New(32, nil)
	hash.Write(sharedSecret)
	digest := hash.Sum(nil)

	signature := make([]byte, mldsa87.SignatureSize)
	err = mldsa87.SignTo(sc.localCert.PrivateKey, digest, []byte{}, false, signature)
	if err != nil {
		return fmt.Errorf("failed to sign shared secret: %w", err)
	}

	// Send signature
	if err := sc.sendMessage(signature); err != nil {
		return fmt.Errorf("failed to send signature: %w", err)
	}

	sc.sharedKey = sharedSecret
	if err := sc.deriveKeys(); err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	return nil
}

// deriveKeys derives encryption and MAC keys from the shared secret
func (sc *SecureConnection) deriveKeys() error {
	// Use BLAKE3 to derive XChaCha20-Poly1305 key (32 bytes)
	hash := blake3.New(32, nil)
	hash.Write(sc.sharedKey)
	key := hash.Sum(nil)

	// Create XChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("failed to create AEAD cipher: %w", err)
	}
	sc.aead = aead
	return nil
}

// sendMessage sends a message with a length prefix
func (sc *SecureConnection) sendMessage(data []byte) error {
	// Combine length header (4 bytes) and data into single buffer
	message := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(message[:4], uint32(len(data)))
	copy(message[4:], data)

	// Write in a single call
	_, err := sc.conn.Write(message)
	return err
}

// receiveMessage receives a message with a length prefix
func (sc *SecureConnection) receiveMessage() ([]byte, error) {
	// First read the length header
	lengthBuf := make([]byte, 4)
	_, err := io.ReadFull(sc.conn, lengthBuf)
	if err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lengthBuf)

	// Read the data
	data := make([]byte, length)
	_, err = io.ReadFull(sc.conn, data)
	return data, err
}

// Send sends an encrypted message
func (sc *SecureConnection) Send(data []byte) error {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	if sc.aead == nil {
		return errors.New("connection not established")
	}

	// Generate random nonce (24 bytes for XChaCha20-Poly1305)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := sc.aead.Seal(nil, nonce, data, nil)

	// Send nonce + ciphertext
	message := append(nonce, ciphertext...)
	return sc.sendMessage(message)
}

// Receive receives and decrypts a message
func (sc *SecureConnection) Receive() ([]byte, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	if sc.aead == nil {
		return nil, errors.New("connection not established")
	}

	message, err := sc.receiveMessage()
	if err != nil {
		return nil, err
	}

	// Extract nonce and ciphertext
	nonceSize := chacha20poly1305.NonceSizeX
	if len(message) < nonceSize {
		return nil, errors.New("message too short")
	}

	nonce := message[:nonceSize]
	ciphertext := message[nonceSize:]

	// Decrypt and verify
	plaintext, err := sc.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Close closes the connection
func (sc *SecureConnection) Close() error {
	return sc.conn.Close()
}

// GetRemoteCertificate returns the remote certificate
func (sc *SecureConnection) GetRemoteCertificate() *MLDSAPublicCertificate {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.remoteCert
}

// DialSecureConnection establishes a secure connection to the given address
func DialSecureConnection(ctx context.Context, addr string, localCert *MLDSAPrivateCertificate) (*SecureConnection, error) {
	conn, err := kcp.Dial(addr)
	if err != nil {
		return nil, err
	}

	kcpConn, ok := conn.(*kcp.UDPSession)
	if !ok {
		conn.Close()
		return nil, errors.New("invalid connection type")
	}

	sc := NewSecureConnection(kcpConn, localCert, false)
	if err := sc.Handshake(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return sc, nil
}

// DialSecureConnectionWithMembers establishes a secure connection with member store verification
func DialSecureConnectionWithMembers(ctx context.Context, addr string, localCert *MLDSAPrivateCertificate, memberStore *MemberStore) (*SecureConnection, error) {
	conn, err := kcp.Dial(addr)
	if err != nil {
		return nil, err
	}

	kcpConn, ok := conn.(*kcp.UDPSession)
	if !ok {
		conn.Close()
		return nil, errors.New("invalid connection type")
	}

	sc := NewSecureConnectionWithMembers(kcpConn, localCert, false, memberStore)
	if err := sc.Handshake(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return sc, nil
}

// DialSecureConnectionWithTrustStore establishes a secure connection with trust store verification
func DialSecureConnectionWithTrustStore(ctx context.Context, addr string, localCert *MLDSAPrivateCertificate, trustStore *TrustStore) (*SecureConnection, error) {
	conn, err := kcp.Dial(addr)
	if err != nil {
		return nil, err
	}

	kcpConn, ok := conn.(*kcp.UDPSession)
	if !ok {
		conn.Close()
		return nil, errors.New("invalid connection type")
	}

	sc := NewSecureConnectionWithTrustStore(kcpConn, localCert, false, trustStore)
	if err := sc.Handshake(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return sc, nil
}

// ListenSecureConnections listens for secure connections on the given address
func ListenSecureConnections(addr string, localCert *MLDSAPrivateCertificate) (*SecureListener, error) {
	listener, err := kcp.Listen(addr)
	if err != nil {
		return nil, err
	}

	kcpListener, ok := listener.(*kcp.Listener)
	if !ok {
		listener.Close()
		return nil, errors.New("invalid listener type")
	}

	return &SecureListener{
		listener:  kcpListener,
		localCert: localCert,
	}, nil
}

// ListenSecureConnectionsWithMembers listens for secure connections with member store verification
func ListenSecureConnectionsWithMembers(addr string, localCert *MLDSAPrivateCertificate, memberStore *MemberStore) (*SecureListener, error) {
	listener, err := kcp.Listen(addr)
	if err != nil {
		return nil, err
	}

	kcpListener, ok := listener.(*kcp.Listener)
	if !ok {
		listener.Close()
		return nil, errors.New("invalid listener type")
	}

	return &SecureListener{
		listener:    kcpListener,
		localCert:   localCert,
		memberStore: memberStore,
	}, nil
}

// ListenSecureConnectionsWithTrustStore listens for secure connections with trust store verification
func ListenSecureConnectionsWithTrustStore(addr string, localCert *MLDSAPrivateCertificate, trustStore *TrustStore) (*SecureListener, error) {
	listener, err := kcp.Listen(addr)
	if err != nil {
		return nil, err
	}

	kcpListener, ok := listener.(*kcp.Listener)
	if !ok {
		listener.Close()
		return nil, errors.New("invalid listener type")
	}

	return &SecureListener{
		listener:   kcpListener,
		localCert:  localCert,
		trustStore: trustStore,
	}, nil
}

// SecureListener represents a listener for secure connections
type SecureListener struct {
	listener    *kcp.Listener
	localCert   *MLDSAPrivateCertificate
	memberStore *MemberStore
	trustStore  *TrustStore
}

// Accept accepts a new secure connection
func (sl *SecureListener) Accept(ctx context.Context) (*SecureConnection, error) {
	conn, err := sl.listener.Accept()
	if err != nil {
		return nil, err
	}

	kcpConn, ok := conn.(*kcp.UDPSession)
	if !ok {
		conn.Close()
		return nil, errors.New("invalid connection type")
	}

	// Create connection with appropriate authentication mode
	var sc *SecureConnection
	if sl.memberStore != nil {
		sc = NewSecureConnectionWithMembers(kcpConn, sl.localCert, true, sl.memberStore)
	} else if sl.trustStore != nil {
		sc = NewSecureConnectionWithTrustStore(kcpConn, sl.localCert, true, sl.trustStore)
	} else {
		sc = NewSecureConnection(kcpConn, sl.localCert, true)
	}

	if err := sc.Handshake(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return sc, nil
}

// Close closes the listener
func (sl *SecureListener) Close() error {
	return sl.listener.Close()
}
