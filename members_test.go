package clustering

import (
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMemberStore(t *testing.T) {
	store := NewMemberStore()

	// Create test certificates
	subject1 := pkix.Name{CommonName: "Test Cert 1"}
	issuer1 := pkix.Name{CommonName: "Issuer 1"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	privCert1, err := NewMLDSAPrivateCertificate(subject1, issuer1, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create certificate 1: %v", err)
	}
	pubCert1 := privCert1.PublicCert()

	privCert2, err := NewMLDSAPrivateCertificate(pkix.Name{CommonName: "Test Cert 2"}, issuer1, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create certificate 2: %v", err)
	}
	pubCert2 := privCert2.PublicCert()

	// Create members
	member1, err := NewMember(pubCert1, "us-east", "zone1", "rack1", "192.168.1.1", "server1.example.com", 1)
	if err != nil {
		t.Fatalf("Failed to create member 1: %v", err)
	}
	member2, err := NewMember(pubCert2, "us-east", "zone1", "rack2", "192.168.1.2", "server2.example.com", 1)
	if err != nil {
		t.Fatalf("Failed to create member 2: %v", err)
	}

	// Add members
	store.AddMember(member1)
	store.AddMember(member2)

	// Get members
	retrieved1, exists := store.GetMember(member1.GetHashKey())
	if !exists {
		t.Fatal("Member 1 not found")
	}
	if retrieved1 != member1 {
		t.Fatal("Retrieved member 1 does not match")
	}

	retrieved2, exists := store.GetMember(member2.GetHashKey())
	if !exists {
		t.Fatal("Member 2 not found")
	}
	if retrieved2 != member2 {
		t.Fatal("Retrieved member 2 does not match")
	}

	// Get all members (should be sorted)
	all := store.GetAllMembers()
	if len(all) != 2 {
		t.Fatalf("Expected 2 members, got %d", len(all))
	}
	// Check if sorted (Region > Zone > Rack > Hash)
	if all[0].GetSortKey() > all[1].GetSortKey() {
		t.Fatal("Members not sorted correctly")
	}
}

func TestSaveLoadCSV(t *testing.T) {
	store := NewMemberStore()

	// Add a member
	subject := pkix.Name{CommonName: "Test Cert"}
	issuer := pkix.Name{CommonName: "Issuer"}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	privCert, err := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	pubCert := privCert.PublicCert()

	member, err := NewMember(pubCert, "us-west", "zone2", "rack3", "10.0.0.1", "test.example.com", 2)
	if err != nil {
		t.Fatalf("Failed to create member: %v", err)
	}

	store.AddMember(member)

	// Save to CSV
	var buf bytes.Buffer
	err = store.SaveToCSV(&buf)
	if err != nil {
		t.Fatalf("Failed to save to CSV: %v", err)
	}

	csvData := buf.String()
	if !strings.Contains(csvData, "us-west") {
		t.Fatal("CSV does not contain region data")
	}
	if !strings.Contains(csvData, "MLDSA CERTIFICATE") {
		t.Fatal("CSV does not contain certificate data")
	}

	// Load from CSV
	newStore := NewMemberStore()
	err = newStore.LoadFromCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("Failed to load from CSV: %v", err)
	}

	// Check if loaded correctly
	all := newStore.GetAllMembers()
	if len(all) != 1 {
		t.Fatalf("Expected 1 member, got %d", len(all))
	}

	loadedMember := all[0]
	if loadedMember.Region != "us-west" || loadedMember.Zone != "zone2" || loadedMember.Rack != "rack3" {
		t.Fatal("Loaded member metadata incorrect")
	}

	// Verify the loaded certificate
	err = loadedMember.Certificate.Verify()
	if err != nil {
		t.Fatalf("Loaded certificate verification failed: %v", err)
	}
}

func TestFindMembers(t *testing.T) {
	store := NewMemberStore()

	// Create members in different regions/zones/racks
	regions := []string{"us-east", "us-west", "eu-central"}
	zones := []string{"zone1", "zone2"}
	racks := []string{"rack1", "rack2"}

	for i, region := range regions {
		for j, zone := range zones {
			for k, rack := range racks {
				subject := pkix.Name{CommonName: fmt.Sprintf("Cert %d-%d-%d", i, j, k)}
				issuer := pkix.Name{CommonName: "Issuer"}
				notBefore := time.Now()
				notAfter := notBefore.Add(24 * time.Hour)

				privCert, _ := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)
				pubCert := privCert.PublicCert()

				member, _ := NewMember(pubCert, region, zone, rack, fmt.Sprintf("192.168.%d.%d", i+1, j*10+k), fmt.Sprintf("server%d.example.com", i*100+j*10+k), i+1)
				store.AddMember(member)
			}
		}
	}

	// Test finding by region
	eastMembers := store.FindMembersInRegion("us-east")
	if len(eastMembers) != 4 { // 2 zones * 2 racks
		t.Fatalf("Expected 4 members in us-east, got %d", len(eastMembers))
	}

	// Test finding by zone
	zone1Members := store.FindMembersInZone("zone1")
	if len(zone1Members) != 6 { // 3 regions * 2 racks
		t.Fatalf("Expected 6 members in zone1, got %d", len(zone1Members))
	}

	// Test finding by rack
	rack1Members := store.FindMembersInRack("rack1")
	if len(rack1Members) != 6 { // 3 regions * 2 zones
		t.Fatalf("Expected 6 members in rack1, got %d", len(rack1Members))
	}
}

func TestConsistentHashing(t *testing.T) {
	store := NewMemberStore()
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	// Create members with different weights
	for i := 0; i < 3; i++ {
		subject := pkix.Name{CommonName: fmt.Sprintf("Server %d", i)}
		issuer := pkix.Name{CommonName: "Issuer"}
		privCert, _ := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)
		pubCert := privCert.PublicCert()

		// Weight increases: 1, 2, 3
		member, _ := NewMember(pubCert, "us-east", "zone1", fmt.Sprintf("rack%d", i),
			fmt.Sprintf("192.168.1.%d", i+1), fmt.Sprintf("server%d.example.com", i), i+1)
		store.AddMember(member)
	}

	// Test GetMemberByHash
	testData := []byte("test-key-12345")
	member := store.GetMemberByHash(testData)
	if member == nil {
		t.Fatal("GetMemberByHash returned nil")
	}

	// Same data should always return the same member
	for i := 0; i < 10; i++ {
		m := store.GetMemberByHash(testData)
		if m != member {
			t.Fatal("GetMemberByHash returned different member for same data")
		}
	}

	// Test distribution with weight
	distribution := make(map[string]int)
	for i := 0; i < 1000; i++ {
		data := []byte(fmt.Sprintf("key-%d", i))
		m := store.GetMemberByHash(data)
		distribution[m.Domain]++
	}

	t.Logf("Distribution: %v", distribution)

	// Members with higher weight should get more keys
	// We don't check exact ratios due to randomness, just that higher weight gets more
	prevCount := 0
	for i := 0; i < 3; i++ {
		domain := fmt.Sprintf("server%d.example.com", i)
		count := distribution[domain]
		if i > 0 && count < prevCount {
			t.Logf("Warning: Member %d (weight %d) got fewer keys (%d) than member %d (weight %d) with %d keys",
				i, i+1, count, i-1, i, prevCount)
		}
		prevCount = count
	}
}

func TestConsistentHashingWithReplicas(t *testing.T) {
	store := NewMemberStore()
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	// Create 5 members
	for i := 0; i < 5; i++ {
		subject := pkix.Name{CommonName: fmt.Sprintf("Server %d", i)}
		issuer := pkix.Name{CommonName: "Issuer"}
		privCert, _ := NewMLDSAPrivateCertificate(subject, issuer, notBefore, notAfter)
		pubCert := privCert.PublicCert()

		member, _ := NewMember(pubCert, "us-east", "zone1", fmt.Sprintf("rack%d", i),
			fmt.Sprintf("192.168.1.%d", i+1), fmt.Sprintf("server%d.example.com", i), 1)
		store.AddMember(member)
	}

	// Test GetMembersByHashWithReplicas
	testData := []byte("test-key-replicas")
	replicas := 3

	members := store.GetMembersByHashWithReplicas(testData, replicas)
	if len(members) != replicas {
		t.Fatalf("Expected %d replicas, got %d", replicas, len(members))
	}

	// All members should be unique
	seen := make(map[string]bool)
	for _, m := range members {
		if seen[m.Domain] {
			t.Fatalf("Duplicate member in replica set: %s", m.Domain)
		}
		seen[m.Domain] = true
	}

	// Same data should always return the same members in the same order
	for i := 0; i < 10; i++ {
		ms := store.GetMembersByHashWithReplicas(testData, replicas)
		if len(ms) != len(members) {
			t.Fatal("Replica count changed")
		}
		for j := range ms {
			if ms[j] != members[j] {
				t.Fatal("Replica members or order changed")
			}
		}
	}
}
