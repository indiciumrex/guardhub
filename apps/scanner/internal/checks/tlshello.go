package checks

// ClientHello construction for tls_config (see probe.RawTLSHello). Each probe
// offers ONE category of cipher suites in a TLS 1.2 ClientHello that looks
// like a normal client (SNI, supported_groups, ec_point_formats,
// signature_algorithms, renegotiation SCSV), so a server's answer reflects its
// configuration, not an odd hello. A suite counts as accepted only when the
// ServerHello picks one of the suites we offered.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
)

// Cipher suite categories (IANA ids). RC4 counts as insecure: RFC 7465
// prohibits it and browsers removed it years ago.
var (
	suitesInsecure = []uint16{
		// NULL encryption
		0x0001, 0x0002, 0x003B, 0xC006, 0xC010, 0xC015,
		// anonymous (no authentication)
		0x0018, 0x001B, 0x0034, 0x003A, 0x006C, 0x006D, 0x00A6, 0x00A7, 0xC016, 0xC017, 0xC018, 0xC019,
		// export grade
		0x0003, 0x0006, 0x0008, 0x000B, 0x000E, 0x0011, 0x0014, 0x0017, 0x0019,
		// single DES
		0x0009, 0x000C, 0x000F, 0x0012, 0x0015, 0x001A,
		// RC4
		0x0004, 0x0005, 0xC002, 0xC007, 0xC00C, 0xC011,
	}
	suites3DES = []uint16{0x000A, 0x000D, 0x0010, 0x0013, 0x0016, 0xC003, 0xC008, 0xC00D, 0xC012}
	// (EC)DHE key exchange, authenticated, modern ciphers: forward secrecy.
	suitesForwardSecret = []uint16{
		0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009E, 0x009F, 0xCCAA,
		0xC023, 0xC027, 0xC024, 0xC028, 0xC009, 0xC013, 0xC00A, 0xC014, 0x0067, 0x006B, 0x0033, 0x0039,
	}
	// static RSA key exchange: no forward secrecy.
	suitesStaticRSA = []uint16{0x009C, 0x009D, 0x003C, 0x003D, 0x002F, 0x0035}
)

const scsvRenegotiation = 0x00FF

// buildClientHello returns one TLS record holding a TLS 1.2 ClientHello that
// offers exactly suites (plus the renegotiation SCSV). serverName is sent as
// SNI unless it is an IP address.
func buildClientHello(serverName string, suites []uint16) []byte {
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, uint16(0x0303)) // client_version TLS 1.2
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	body.Write(random)
	body.WriteByte(0) // empty session id
	_ = binary.Write(&body, binary.BigEndian, uint16(2*(len(suites)+1)))
	for _, s := range suites {
		_ = binary.Write(&body, binary.BigEndian, s)
	}
	_ = binary.Write(&body, binary.BigEndian, uint16(scsvRenegotiation))
	body.Write([]byte{1, 0}) // compression: null only

	var ext bytes.Buffer
	if serverName != "" && net.ParseIP(serverName) == nil {
		name := []byte(serverName)
		writeExt(&ext, 0x0000, func(b *bytes.Buffer) { // server_name
			_ = binary.Write(b, binary.BigEndian, uint16(len(name)+3))
			b.WriteByte(0) // host_name
			_ = binary.Write(b, binary.BigEndian, uint16(len(name)))
			b.Write(name)
		})
	}
	writeExt(&ext, 0x000A, func(b *bytes.Buffer) { // supported_groups: x25519, P-256, P-384, P-521, ffdhe2048
		groups := []uint16{0x001D, 0x0017, 0x0018, 0x0019, 0x0100}
		_ = binary.Write(b, binary.BigEndian, uint16(2*len(groups)))
		for _, g := range groups {
			_ = binary.Write(b, binary.BigEndian, g)
		}
	})
	writeExt(&ext, 0x000B, func(b *bytes.Buffer) { b.Write([]byte{1, 0}) }) // ec_point_formats: uncompressed
	writeExt(&ext, 0x000D, func(b *bytes.Buffer) {                          // signature_algorithms
		algs := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201, 0x0203}
		_ = binary.Write(b, binary.BigEndian, uint16(2*len(algs)))
		for _, a := range algs {
			_ = binary.Write(b, binary.BigEndian, a)
		}
	})
	_ = binary.Write(&body, binary.BigEndian, uint16(ext.Len()))
	body.Write(ext.Bytes())

	hs := []byte{1, byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())}
	hs = append(hs, body.Bytes()...)
	rec := []byte{22, 3, 1, byte(len(hs) >> 8), byte(len(hs))} // record version TLS 1.0 for compatibility
	return append(rec, hs...)
}

func writeExt(dst *bytes.Buffer, typ uint16, fill func(*bytes.Buffer)) {
	var b bytes.Buffer
	fill(&b)
	_ = binary.Write(dst, binary.BigEndian, typ)
	_ = binary.Write(dst, binary.BigEndian, uint16(b.Len()))
	dst.Write(b.Bytes())
}

func offered(suites []uint16, s uint16) bool {
	for _, x := range suites {
		if x == s {
			return true
		}
	}
	return false
}
