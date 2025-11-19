package clustering

import (
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/zeebo/xxh3"
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
	Weight      int    // weight for consistent hashing (default: 1)
	hashKey     string // internal Blake3 hash
	sortKey     string // Region|Zone|Rack|hashKey for sorting
}

// NewMember creates a new member with certificate and metadata.
func NewMember(cert *MLDSAPublicCertificate, region, zone, rack, ip, domain string, weight int) (*Member, error) {
	pemData, err := cert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	if weight <= 0 {
		weight = 1 // default weight
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
		Weight:      weight,
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
	members     []*Member
	hashRanges  []hashRange // hash ranges for consistent hashing
	totalWeight int         // sum of all member weights
}

// hashRange represents a member's range on the consistent hash ring.
type hashRange struct {
	startHash uint64  // starting point of this range
	member    *Member // member owning this range
}

// NewMemberStore creates a new member store.
func NewMemberStore() *MemberStore {
	return &MemberStore{
		members: make([]*Member, 0),
	}
}

// AddMember adds a member to the store, keeping it sorted.
func (ms *MemberStore) AddMember(member *Member) {
	ms.members = append(ms.members, member)
	ms.sortMembers()
	ms.rebuildHashRanges()
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

// RemoveMember removes a member from the store and rebuilds hash ranges.
func (ms *MemberStore) RemoveMember(hashKey string) bool {
	for i, member := range ms.members {
		if member.hashKey == hashKey {
			ms.members = append(ms.members[:i], ms.members[i+1:]...)
			ms.rebuildHashRanges()
			return true
		}
	}
	return false
}

// GetAllMembers returns all members (already sorted).
func (ms *MemberStore) GetAllMembers() []*Member {
	return ms.members
}

// sortMembers sorts members by Region > Zone > Rack > Hash Key.
func (ms *MemberStore) sortMembers() {
	slices.SortFunc(ms.members, func(a, b *Member) int {
		if a.sortKey < b.sortKey {
			return -1
		}
		if a.sortKey > b.sortKey {
			return 1
		}
		return 0
	})
}

// SaveToCSV saves the members to CSV format (already sorted).
func (ms *MemberStore) SaveToCSV(writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{"Region", "Zone", "Rack", "IP", "Domain", "Weight", "HashKey", "PEMData"}
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
			strconv.Itoa(member.Weight),
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
		if len(record) != 8 {
			return fmt.Errorf("invalid CSV record: expected 8 fields, got %d", len(record))
		}
		region := record[0]
		zone := record[1]
		rack := record[2]
		ip := record[3]
		domain := record[4]
		weightStr := record[5]
		hashKey := record[6]
		pemData := record[7]

		weight, err := strconv.Atoi(weightStr)
		if err != nil {
			return fmt.Errorf("invalid weight value: %w", err)
		}
		if weight <= 0 {
			weight = 1
		}

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
			Weight:      weight,
			hashKey:     hashKey,
			sortKey:     sortKey,
		}

		ms.members = append(ms.members, member)
	}

	// Ensure sorted
	ms.sortMembers()
	ms.rebuildHashRanges()
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

// rebuildHashRanges builds hash ranges for consistent hashing.
// Divides the hash space (0 to 2^64-1) into ranges proportional to member weights.
func (ms *MemberStore) rebuildHashRanges() {
	if len(ms.members) == 0 {
		ms.hashRanges = nil
		ms.totalWeight = 0
		return
	}

	// Calculate total weight
	ms.totalWeight = 0
	for _, member := range ms.members {
		ms.totalWeight += member.Weight
	}

	// Build hash ranges
	ms.hashRanges = make([]hashRange, 0, len(ms.members))
	var currentHash uint64 = 0

	for i, member := range ms.members {
		ms.hashRanges = append(ms.hashRanges, hashRange{
			startHash: currentHash,
			member:    member,
		})

		// Calculate range size based on weight proportion
		if i < len(ms.members)-1 {
			// For all but the last member, calculate proportional range
			rangeSize := (^uint64(0) / uint64(ms.totalWeight)) * uint64(member.Weight)
			currentHash += rangeSize
		}
		// Last member gets the remaining range to wrap around to 0
	}
}

// GetMemberByHash finds the appropriate member for the given data using consistent hashing with xxh3.
// Uses hash ranges instead of virtual nodes for better memory efficiency.
func (ms *MemberStore) GetMemberByHash(data []byte) *Member {
	if len(ms.hashRanges) == 0 {
		return nil
	}

	// Hash the input data
	dataHash := xxh3.Hash(data)

	// Find the range containing this hash using binary search
	idx, found := slices.BinarySearchFunc(ms.hashRanges, dataHash, func(hr hashRange, target uint64) int {
		if target < hr.startHash {
			return 1 // target is before this range
		}
		return -1 // keep searching
	})

	if !found {
		// BinarySearchFunc returns the insertion point
		// We want the range just before the insertion point
		if idx > 0 {
			idx--
		} else {
			// Wrap around to the last range
			idx = len(ms.hashRanges) - 1
		}
	}

	return ms.hashRanges[idx].member
}

// GetMembersByHashWithReplicas finds N members for the given data using consistent hashing.
// This is useful for replication scenarios where data should be stored on multiple nodes.
func (ms *MemberStore) GetMembersByHashWithReplicas(data []byte, replicas int) []*Member {
	if len(ms.hashRanges) == 0 || replicas <= 0 {
		return nil
	}

	// Hash the input data
	dataHash := xxh3.Hash(data)

	// Find the range containing this hash
	idx, found := slices.BinarySearchFunc(ms.hashRanges, dataHash, func(hr hashRange, target uint64) int {
		if target < hr.startHash {
			return 1
		}
		return -1
	})

	if !found {
		if idx > 0 {
			idx--
		} else {
			idx = len(ms.hashRanges) - 1
		}
	}

	// Collect unique members by walking the ring
	result := make([]*Member, 0, replicas)
	seen := make(map[string]bool)

	for i := 0; len(result) < replicas && len(result) < len(ms.members); i++ {
		currentIdx := (idx + i) % len(ms.hashRanges)
		member := ms.hashRanges[currentIdx].member

		if !seen[member.hashKey] {
			result = append(result, member)
			seen[member.hashKey] = true
		}
	}

	return result
}
