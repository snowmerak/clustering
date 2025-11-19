# Clustering with Post-Quantum Cryptography

This project implements a secure clustering library and PKI system using Post-Quantum Cryptography (PQC). It leverages **ML-DSA (Dilithium)** for digital signatures and certificates, and **ML-KEM (Kyber)** for secure key exchange, ensuring resistance against future quantum computer attacks.

The library provides a secure communication layer over **KCP** (a fast and reliable UDP protocol) and includes a consistent hashing mechanism for managing cluster members.

## Features

*   **Post-Quantum Security**:
    *   **ML-DSA (Dilithium)**: Used for custom X.509-like certificates and digital signatures.
    *   **ML-KEM (Kyber)**: Used for secure key encapsulation and exchange during handshakes.
*   **Custom PKI**:
    *   Full support for Root CA, Intermediate CA, and Leaf certificates.
    *   PEM encoding/decoding for keys and certificates.
    *   TrustStore implementation for verifying certificate chains.
*   **Secure Communication**:
    *   Built on top of **KCP** (UDP) for low latency.
    *   **XChaCha20-Poly1305** for authenticated encryption of data.
    *   Tiered authentication: MemberStore (whitelist) > TrustStore (PKI) > Self-Signed.
*   **Cluster Management**:
    *   **MemberStore**: Manages cluster members with metadata (Region, Zone, Rack, IP, etc.).
    *   **Consistent Hashing**: Distributes data or requests across members using weighted consistent hashing (XXH3).
    *   CSV import/export for member configurations.

## Installation

```bash
go get github.com/snowmerak/clustering
```

## CLI Tool: `cpki`

The `cpki` (Cluster PKI) tool is a command-line utility included in this project to generate ML-DSA certificates.

### Build

```bash
go build -o cpki.exe ./cmd/cpki
```

### Usage

The tool supports generating Root CAs, Intermediate CAs, and Leaf certificates.

#### 1. Generate Root CA
```bash
./cpki.exe root -cn "My Root CA" -out-cert root.crt -out-key root.key -days 3650
```

#### 2. Generate Intermediate CA
Signed by the Root CA.
```bash
./cpki.exe intermediate -ca-cert root.crt -ca-key root.key -cn "My Intermediate CA" -out-cert intermediate.crt -out-key intermediate.key -days 1825
```

#### 3. Generate Leaf Certificate
Signed by the Intermediate CA (or Root CA).
```bash
./cpki.exe leaf -ca-cert intermediate.crt -ca-key intermediate.key -cn "My Leaf Node" -out-cert leaf.crt -out-key leaf.key -days 365
```

## Library Usage

### 1. Secure Connection (Server & Client)

**Server:**
```go
// Load server certificate and key
certBytes, _ := os.ReadFile("leaf.crt")
keyBytes, _ := os.ReadFile("leaf.key")
cert, _ := clustering.UnmarshalPEM(certBytes)
privKey, _ := clustering.UnmarshalPrivateKeyPEM(keyBytes)

localCert := &clustering.MLDSAPrivateCertificate{
    PublicCertificate: *cert,
    PrivateKey:        privKey,
}

// Start listener
listener, _ := clustering.ListenSecureConnections("127.0.0.1:8080", localCert)
for {
    conn, _ := listener.Accept(context.Background())
    // Handle connection...
}
```

**Client:**
```go
// Load client certificate (optional, but recommended for mutual auth)
// ... (load localCert as above)

// Connect to server
conn, _ := clustering.DialSecureConnection(context.Background(), "127.0.0.1:8080", localCert)

// Send data
conn.Send([]byte("Hello Secure World"))
```

### 2. Using TrustStore

To enforce that peers must present a certificate signed by a trusted Root CA:

```go
// Load Root CA
rootCertBytes, _ := os.ReadFile("root.crt")
rootCert, _ := clustering.UnmarshalPEM(rootCertBytes)

// Create TrustStore
trustStore := clustering.NewTrustStore()
trustStore.AddRootCA(rootCert)

// Use TrustStore in Listener or Dialer
listener, _ := clustering.ListenSecureConnectionsWithTrustStore("127.0.0.1:8080", localCert, trustStore)
// OR
conn, _ := clustering.DialSecureConnectionWithTrustStore(ctx, "127.0.0.1:8080", localCert, trustStore)
```

### 3. Cluster Member Management

```go
store := clustering.NewMemberStore()

// Add a member
member, _ := clustering.NewMember(cert, "us-east", "zone-a", "rack-1", "10.0.0.1", "node1.example.com", 10)
store.AddMember(member)

// Find member for a piece of data (Consistent Hashing)
data := []byte("some-key")
targetMember := store.GetMemberByHash(data)
fmt.Printf("Data belongs to node: %s\n", targetMember.IP)
```

## Testing

Run the included tests to verify functionality:

```bash
go test ./...
```
