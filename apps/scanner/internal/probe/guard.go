package probe

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

// ErrBlockedAddress is returned when a connection would reach an address
// the scanner must never touch (loopback, private, link-local, metadata…).
var ErrBlockedAddress = errors.New("probe: destination address is not allowed")

// BlockedError carries the refused IP. errors.Is(err, ErrBlockedAddress) is true.
type BlockedError struct{ IP netip.Addr }

func (e *BlockedError) Error() string {
	return fmt.Sprintf("probe: destination %s is not a public address", e.IP)
}

// Is makes errors.Is(err, ErrBlockedAddress) work.
func (e *BlockedError) Is(target error) bool { return target == ErrBlockedAddress }

// blockedPrefixes are special-purpose ranges that the netip helpers below do
// not already cover.
var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",          // "this network"
	"100.64.0.0/10",      // CGNAT (RFC 6598)
	"192.0.0.0/24",       // IETF protocol assignments
	"192.0.2.0/24",       // TEST-NET-1
	"192.88.99.0/24",     // 6to4 relay anycast
	"198.18.0.0/15",      // benchmarking
	"198.51.100.0/24",    // TEST-NET-2
	"203.0.113.0/24",     // TEST-NET-3
	"240.0.0.0/4",        // reserved + broadcast
	"::/96",              // IPv4-compatible (deprecated)
	"100::/64",           // discard-only
	"2001::/32",          // Teredo
	"2001:db8::/32",      // documentation
	"fec0::/10",          // site-local (deprecated)
	"64:ff9b:1::/48",     // local-use NAT64
	"169.254.169.254/32", // cloud metadata (also link-local; explicit for clarity)
	"fd00:ec2::254/128",  // AWS IMDS over IPv6 (also ULA)
)

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour   = netip.MustParsePrefix("2002::/16")
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// IsBlockedIP reports whether ip must never be dialled. It unwraps
// IPv4-mapped (::ffff:a.b.c.d), NAT64 (64:ff9b::/96) and 6to4 (2002::/16)
// addresses and checks the embedded IPv4 address too.
func IsBlockedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		b := ip.As16()
		if nat64Prefix.Contains(ip) {
			return IsBlockedIP(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
		}
		if sixToFour.Contains(ip) {
			if IsBlockedIP(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})) {
				return true
			}
		}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// guardControl is installed as net.Dialer.Control. It runs after DNS
// resolution, on the exact IP that is about to be connected, so it also
// defeats DNS rebinding.
func guardControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparsable address %q", ErrBlockedAddress, address)
	}
	if IsBlockedIP(ap.Addr()) {
		return &BlockedError{IP: ap.Addr()}
	}
	return nil
}
