package clustering

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"

	"lukechampine.com/blake3"
)

// Member represents a cluster member with certificate and metadata.
type Member struct {
	Certificate *MLDSAPublicCertificate
	Region      string
	Zone        string
	Rack        string
	IP          string
	Domain      string
	hashKey     string // internal Blake3 hash
	sortKey     string // Region|Zone|Rack|hashKey for sorting
}

// NewMember creates a new member with certificate and metadata.
func NewMember(cert *MLDSAPublicCertificate, region, zone, rack, ip, domain string) (*Member, error) {
	pemData, err := cert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	hasher := blake3.New(32, nil)
	hasher.Write(pemData)
	hashKey := fmt.Sprintf("%x", hasher.Sum(nil))

	sortKey := fmt.Sprintf("%-20s|%-20s|%-20s|%s", region, zone, rack, hashKey)

	return &Member{
		Certificate: cert,
		Region:      region,
		Zone:        zone,
		Rack:        rack,
		IP:          ip,
		Domain:      domain,
		hashKey:     hashKey,
		sortKey:     sortKey,
	}, nil
}

// GetHashKey returns the Blake3 hash key.
func (m *Member) GetHashKey() string {
	return m.hashKey
}

// GetSortKey returns the sort key.
func (m *Member) GetSortKey() string {
	return m.sortKey
}

// MemberStore manages members stored as sorted CSV.
type MemberStore struct {
	members []*Member
}

// NewMemberStore creates a new member store.
func NewMemberStore() *MemberStore {
	return &MemberStore{
		members: make([]*Member, 0),
	}
}

// AddMember adds a member to the store and keeps it sorted.
func (ms *MemberStore) AddMember(member *Member) {
	ms.members = append(ms.members, member)
	ms.sortMembers()
}

// GetMember retrieves a member by its hash key.
func (ms *MemberStore) GetMember(hashKey string) (*Member, bool) {
	for _, member := range ms.members {
		if member.hashKey == hashKey {
			return member, true
		}
	}
	return nil, false
}

// GetAllMembers returns all members (already sorted).
func (ms *MemberStore) GetAllMembers() []*Member {
	return ms.members
}

// sortMembers sorts members by Region > Zone > Rack > Hash Key.
func (ms *MemberStore) sortMembers() {
	sort.Slice(ms.members, func(i, j int) bool {
		return ms.members[i].sortKey < ms.members[j].sortKey
	})
}

// SaveToCSV saves the members to CSV format (already sorted).
func (ms *MemberStore) SaveToCSV(writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{"Region", "Zone", "Rack", "IP", "Domain", "HashKey", "PEMData"}
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, member := range ms.members {
		pemData, err := member.Certificate.MarshalPEM()
		if err != nil {
			return fmt.Errorf("failed to marshal certificate for %s: %w", member.hashKey, err)
		}
		record := []string{
			member.Region,
			member.Zone,
			member.Rack,
			member.IP,
			member.Domain,
			member.hashKey,
			string(pemData),
		}
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}
	return nil
}

// LoadFromCSV loads members from CSV format and sorts them.
func (ms *MemberStore) LoadFromCSV(reader io.Reader) error {
	csvReader := csv.NewReader(reader)
	records, err := csvReader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read CSV: %w", err)
	}

	if len(records) == 0 {
		return nil
	}

	// Skip header
	records = records[1:]

	ms.members = make([]*Member, 0, len(records))
	for _, record := range records {
		if len(record) != 7 {
			return fmt.Errorf("invalid CSV record: expected 7 fields, got %d", len(record))
		}
		region := record[0]
		zone := record[1]
		rack := record[2]
		ip := record[3]
		domain := record[4]
		hashKey := record[5]
		pemData := record[6]

		cert, err := UnmarshalPEM([]byte(pemData))
		if err != nil {
			return fmt.Errorf("failed to unmarshal certificate for %s: %w", hashKey, err)
		}

		// Verify the hash key
		expectedHasher := blake3.New(32, nil)
		expectedHasher.Write([]byte(pemData))
		expectedHashKey := fmt.Sprintf("%x", expectedHasher.Sum(nil))
		if hashKey != expectedHashKey {
			return fmt.Errorf("hash key mismatch for certificate: expected %s, got %s", expectedHashKey, hashKey)
		}

		// Reconstruct sort key
		sortKey := fmt.Sprintf("%-20s|%-20s|%-20s|%s", region, zone, rack, hashKey)

		member := &Member{
			Certificate: cert,
			Region:      region,
			Zone:        zone,
			Rack:        rack,
			IP:          ip,
			Domain:      domain,
			hashKey:     hashKey,
			sortKey:     sortKey,
		}

		ms.members = append(ms.members, member)
	}

	// Ensure sorted
	ms.sortMembers()
	return nil
}

// FindMembersInRegion returns members in a specific region.
func (ms *MemberStore) FindMembersInRegion(region string) []*Member {
	var result []*Member
	for _, member := range ms.members {
		if member.Region == region {
			result = append(result, member)
		}
	}
	return result
}

// FindMembersInZone returns members in a specific zone.
func (ms *MemberStore) FindMembersInZone(zone string) []*Member {
	var result []*Member
	for _, member := range ms.members {
		if member.Zone == zone {
			result = append(result, member)
		}
	}
	return result
}

// FindMembersInRack returns members in a specific rack.
func (ms *MemberStore) FindMembersInRack(rack string) []*Member {
	var result []*Member
	for _, member := range ms.members {
		if member.Rack == rack {
			result = append(result, member)
		}
	}
	return result
}
