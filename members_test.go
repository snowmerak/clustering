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
	member1, err := NewMember(pubCert1, "us-east", "zone1", "rack1", "192.168.1.1", "server1.example.com")
	if err != nil {
		t.Fatalf("Failed to create member 1: %v", err)
	}
	member2, err := NewMember(pubCert2, "us-east", "zone1", "rack2", "192.168.1.2", "server2.example.com")
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

	member, err := NewMember(pubCert, "us-west", "zone2", "rack3", "10.0.0.1", "test.example.com")
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

				member, _ := NewMember(pubCert, region, zone, rack, fmt.Sprintf("192.168.%d.%d", i+1, j*10+k), fmt.Sprintf("server%d.example.com", i*100+j*10+k))
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
