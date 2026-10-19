package admin

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// egressEnrollment is the only hook that may supply a live network namespace
// for a nonempty grant set. The owner has already configured forwarding and
// retains the descriptor; the helper only pins and inherits it.
type egressEnrollment struct {
	Namespace       *os.File
	EndpointIDs     []api.ID
	PolicySHA256    api.Digest
	ClaimID         api.ID
	ClaimGeneration api.Generation
	owner           *namespaceOwner
}

type egressResolver func(context.Context, leaseRecord, []api.NetworkGrant) (egressEnrollment, error)

// ValidateNetworkGrant reads the same immutable administrator launch enrollment
// used by the native helper. Approval issues a capability, not a namespace.
func (s *Service) ValidateNetworkGrant(ctx context.Context, config string, grant api.NetworkGrant) error {
	if config != s.deps.Config {
		return failure(api.CodeForbidden, "network enrollment belongs to another configuration")
	}
	enrollment, _, err := s.loadLaunchEnrollment(ctx)
	if err != nil {
		return err
	}
	_, err = enrolledNetwork(enrollment, grant, time.Now())
	return err
}

func enrolledNetwork(enrollment api.LaunchEnrollment, grant api.NetworkGrant, now time.Time) (api.NetworkEndpoint, error) {
	expiry, err := time.Parse(time.RFC3339Nano, string(grant.ExpiresAt))
	if err != nil || !expiry.After(now) || grant.EndpointID != "anthropic-api" || grant.Mode != "internet" {
		return api.NetworkEndpoint{}, failure(api.CodeForbidden, "network grant is stale or outside the enrolled API scope")
	}
	for _, endpoint := range enrollment.Network {
		if endpoint.ID == grant.EndpointID && endpoint.Host == "api.anthropic.com" && endpoint.Protocol == "tcp" && endpoint.Port == 443 {
			return endpoint, nil
		}
	}
	return api.NetworkEndpoint{}, failure(api.CodeForbidden, "Anthropic API endpoint is not enrolled")
}

// Reject the entire answer on rebinding, including a mixed public/private
// answer. IPv6 is checked but not routed or advertised by this IPv4 lease.
func egressAddresses(answer, host []netip.Addr) ([]netip.Addr, error) {
	blocked := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10"}
	seen := map[netip.Addr]bool{}
	var pins []netip.Addr
	if len(answer) == 0 || len(answer) > 64 {
		return nil, errors.New("API DNS answer is empty or exceeds its bound")
	}
	for _, ip := range answer {
		if !ip.IsValid() || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return nil, errors.New("API DNS answer contains a nonpublic address")
		}
		for _, prefix := range blocked {
			if netip.MustParsePrefix(prefix).Contains(ip) {
				return nil, errors.New("API DNS answer contains a reserved address")
			}
		}
		for _, local := range host {
			if ip == local.Unmap() {
				return nil, errors.New("API DNS answer contains a host address")
			}
		}
		if ip.Is4() && !seen[ip] {
			pins, seen[ip] = append(pins, ip), true
		}
	}
	if len(pins) == 0 {
		return nil, errors.New("API DNS answer has no routable IPv4 address")
	}
	sort.Slice(pins, func(i, j int) bool { return pins[i].Less(pins[j]) })
	return pins, nil
}

// The namespace resolver answers only this enrolled name from the current
// firewall pins. It never forwards a caller-controlled DNS name upstream.
func egressDNS(query []byte, pins []netip.Addr) []byte {
	if len(query) < 17 || len(query) > 4096 || binary.BigEndian.Uint16(query[2:4])&0xf800 != 0 ||
		binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil
	}
	offset, labels := 12, []string{}
	for {
		if offset >= len(query) {
			return nil
		}
		size := int(query[offset])
		offset++
		if size == 0 {
			break
		}
		if size > 63 || offset+size > len(query) || offset > 267 {
			return nil
		}
		labels = append(labels, string(query[offset:offset+size]))
		offset += size
	}
	if offset+4 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])
	class := binary.BigEndian.Uint16(query[offset+2 : offset+4])
	response := append([]byte{}, query[:offset+4]...)
	flags := uint16(0x8080) | binary.BigEndian.Uint16(query[2:4])&0x0100
	if !strings.EqualFold(strings.Join(labels, "."), "api.anthropic.com") || class != 1 || len(pins) == 0 {
		flags |= 5 // REFUSED; no upstream query, including on an expired lease.
	} else if qtype == 1 {
		for _, ip := range pins {
			address := ip.As4()
			response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
			response = append(response, address[:]...)
		}
		binary.BigEndian.PutUint16(response[6:8], uint16(len(pins)))
	}
	binary.BigEndian.PutUint16(response[2:4], flags)
	if flags&15 != 0 || qtype != 1 {
		binary.BigEndian.PutUint16(response[6:8], 0)
	}
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	return response
}
