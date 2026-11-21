package probe

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// serverHello builds a ServerHello record (optionally with supported_versions).
func serverHello(legacy, suite uint16, supported uint16) []byte {
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, legacy)
	body.Write(make([]byte, 32)) // random
	body.WriteByte(32)
	body.Write(bytes.Repeat([]byte{0xAB}, 32)) // session id
	_ = binary.Write(&body, binary.BigEndian, suite)
	body.WriteByte(0) // compression
	var ext bytes.Buffer
	_ = binary.Write(&ext, binary.BigEndian, uint16(0xff01)) // renegotiation_info
	_ = binary.Write(&ext, binary.BigEndian, uint16(1))
	ext.WriteByte(0)
	if supported != 0 {
		_ = binary.Write(&ext, binary.BigEndian, uint16(extSupportedVers))
		_ = binary.Write(&ext, binary.BigEndian, uint16(2))
		_ = binary.Write(&ext, binary.BigEndian, supported)
	}
	_ = binary.Write(&body, binary.BigEndian, uint16(ext.Len()))
	body.Write(ext.Bytes())
	hs := append([]byte{handshakeSH, 0, byte(body.Len() >> 8), byte(body.Len())}, body.Bytes()...)
	return record(recordHandshake, hs)
}

func record(typ byte, payload []byte) []byte {
	return append([]byte{typ, 3, 3, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func TestParseServerHello(t *testing.T) {
	tls12 := serverHello(0x0303, 0xC02F, 0)
	tls13 := serverHello(0x0303, 0x1301, 0x0304)
	cases := []struct {
		name    string
		in      []byte
		done    bool
		outcome HelloOutcome
		version uint16
		suite   uint16
		alert   byte
	}{
		{"tls1.2 accepted", tls12, true, HelloAccepted, 0x0303, 0xC02F, 0},
		{"tls1.3 via supported_versions", tls13, true, HelloAccepted, 0x0304, 0x1301, 0},
		{"handshake_failure alert", record(recordAlert, []byte{2, 40}), true, HelloRejected, 0, 0, 40},
		{"protocol_version alert", record(recordAlert, []byte{2, 70}), true, HelloRejected, 0, 0, 70},
		{"incomplete record", tls12[:20], false, 0, 0, 0, 0},
		{"empty", nil, false, 0, 0, 0, 0},
		{"http answer", []byte("HTTP/1.1 400 Bad Request\r\n\r\n"), true, HelloNotTLS, 0, 0, 0},
		{"ServerHello followed by Certificate in the same read", append(append([]byte{}, tls12...), record(recordHandshake, []byte{11, 0, 0, 0})...), true, HelloAccepted, 0x0303, 0xC02F, 0},
	}
	for _, c := range cases {
		res, done := ParseServerHello(c.in)
		if done != c.done {
			t.Fatalf("%s: done=%v", c.name, done)
		}
		if !done {
			continue
		}
		if res.Outcome != c.outcome || res.Version != c.version || res.CipherSuite != c.suite || res.Alert != c.alert {
			t.Errorf("%s: %+v", c.name, res)
		}
	}
}

// A ServerHello split over two records (allowed by RFC 8446 §5.1) is reassembled.
func TestParseServerHelloAcrossRecords(t *testing.T) {
	whole := serverHello(0x0303, 0x009C, 0)
	hs := whole[5:]
	split := append(record(recordHandshake, hs[:10]), record(recordHandshake, hs[10:])...)
	if res, done := ParseServerHello(split[:len(split)-3]); done {
		t.Fatalf("must wait for the rest, got %+v", res)
	}
	res, done := ParseServerHello(split)
	if !done || res.Outcome != HelloAccepted || res.CipherSuite != 0x009C {
		t.Fatalf("%+v %v", res, done)
	}
}
