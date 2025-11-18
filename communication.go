package clustering

import (
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// SecureConnection represents a secure connection using KCP with ML-DSA certificates and ML-KEM key exchange
type SecureConnection struct {
	conn       *kcp.UDPSession
	localCert  *MLDSAPrivateCertificate
	remoteCert *MLDSAPublicCertificate
	sharedKey  []byte
	aead       cipher.AEAD
	isServer   bool
	mu         sync.RWMutex
}

// NewSecureConnection creates a new secure connection
func NewSecureConnection(conn *kcp.UDPSession, localCert *MLDSAPrivateCertificate, isServer bool) *SecureConnection {
	return &SecureConnection{
		conn:      conn,
		localCert: localCert,
		isServer:  isServer,
	}
}

// Handshake performs the certificate-based handshake and key exchange
func (sc *SecureConnection) Handshake() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.isServer {
		return sc.serverHandshake()
	}
	return sc.clientHandshake()
}

// clientHandshake performs the client-side handshake
func (sc *SecureConnection) clientHandshake() error {
	// Send local certificate
	certPEM, err := sc.localCert.PublicCert().MarshalPEM()
	if err != nil {
		return fmt.Errorf("failed to marshal certificate: %w", err)
	}

	if err := sc.sendMessage(certPEM); err != nil {
		return fmt.Errorf("failed to send certificate: %w", err)
	}

	// Receive server certificate
	serverCertPEM, err := sc.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive server certificate: %w", err)
	}

	serverCert, err := UnmarshalPEM(serverCertPEM)
	if err != nil {
		return fmt.Errorf("failed to unmarshal server certificate: %w", err)
	}

	// Verify server certificate (in a real implementation, you'd verify against a trusted CA)
	if err := serverCert.Verify(); err != nil {
		return fmt.Errorf("server certificate verification failed: %w", err)
	}

	sc.remoteCert = serverCert

	// Perform ML-KEM key exchange
	if err := sc.performKeyExchange(); err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	return nil
}

// serverHandshake performs the server-side handshake
func (sc *SecureConnection) serverHandshake() error {
	// Receive client certificate
	clientCertPEM, err := sc.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive client certificate: %w", err)
	}

	clientCert, err := UnmarshalPEM(clientCertPEM)
	if err != nil {
		return fmt.Errorf("failed to unmarshal client certificate: %w", err)
	}

	// Verify client certificate
	if err := clientCert.Verify(); err != nil {
		return fmt.Errorf("client certificate verification failed: %w", err)
	}

	sc.remoteCert = clientCert

	// Send server certificate
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
	hash, err := blake2b.New256(nil)
	if err != nil {
		return fmt.Errorf("failed to create hash: %w", err)
	}
	hash.Write(sharedSecret)
	digest := hash.Sum(nil)

	if !mldsa87.Verify(sc.remoteCert.GetPublicKey(), digest, []byte{}, signature) {
		return errors.New("server signature verification failed")
	}

	sc.sharedKey = sharedSecret
	sc.deriveKeys()

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
	hash, err := blake2b.New256(nil)
	if err != nil {
		return fmt.Errorf("failed to create hash: %w", err)
	}
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
	sc.deriveKeys()

	return nil
}

// deriveKeys derives encryption and MAC keys from the shared secret
func (sc *SecureConnection) deriveKeys() {
	// Use BLAKE2b-256 to derive XChaCha20-Poly1305 key (32 bytes)
	hash, _ := blake2b.New256(nil)
	hash.Write(sc.sharedKey)
	key := hash.Sum(nil)

	// Create XChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(fmt.Sprintf("failed to create AEAD cipher: %v", err))
	}
	sc.aead = aead
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
func DialSecureConnection(addr string, localCert *MLDSAPrivateCertificate) (*SecureConnection, error) {
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
	if err := sc.Handshake(); err != nil {
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

// SecureListener represents a listener for secure connections
type SecureListener struct {
	listener  *kcp.Listener
	localCert *MLDSAPrivateCertificate
}

// Accept accepts a new secure connection
func (sl *SecureListener) Accept() (*SecureConnection, error) {
	conn, err := sl.listener.Accept()
	if err != nil {
		return nil, err
	}

	kcpConn, ok := conn.(*kcp.UDPSession)
	if !ok {
		conn.Close()
		return nil, errors.New("invalid connection type")
	}

	sc := NewSecureConnection(kcpConn, sl.localCert, true)
	if err := sc.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	return sc, nil
}

// Close closes the listener
func (sl *SecureListener) Close() error {
	return sl.listener.Close()
}
