package proxyprotocol

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseV2Datagram(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		source      netip.AddrPort
		destination netip.AddrPort
		payload     []byte
	}{
		{
			name:        "IPv4",
			source:      netip.MustParseAddrPort("198.51.100.10:41641"),
			destination: netip.MustParseAddrPort("192.0.2.20:1235"),
			payload:     []byte("stun-v4"),
		},
		{
			name:        "IPv6",
			source:      netip.MustParseAddrPort("[2001:db8::10]:41641"),
			destination: netip.MustParseAddrPort("[2001:db8::20]:1235"),
			payload:     []byte("stun-v6"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			packet := testV2Datagram(tt.source, tt.destination, tt.payload)
			header, payload, err := ParseV2Datagram(packet)
			require.NoError(t, err)
			assert.Equal(t, tt.source, header.Source)
			assert.Equal(t, tt.destination, header.Destination)
			assert.Equal(t, tt.payload, payload)
			assert.Equal(t, len(packet)-len(tt.payload), header.Length)
		})
	}
}

func TestParseV2DatagramRejectsInvalidPackets(t *testing.T) {
	t.Parallel()

	valid := testV2Datagram(
		netip.MustParseAddrPort("198.51.100.10:41641"),
		netip.MustParseAddrPort("192.0.2.20:1235"),
		[]byte("stun"),
	)

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "short", mutate: func(packet []byte) []byte { return packet[:8] }},
		{name: "signature", mutate: func(packet []byte) []byte { packet[0] = 0xff; return packet }},
		{name: "version", mutate: func(packet []byte) []byte { packet[12] = 0x11; return packet }},
		{name: "command", mutate: func(packet []byte) []byte { packet[12] = 0x20; return packet }},
		{name: "transport", mutate: func(packet []byte) []byte { packet[13] = 0x11; return packet }},
		{name: "family", mutate: func(packet []byte) []byte { packet[13] = 0x32; return packet }},
		{name: "length", mutate: func(packet []byte) []byte { binary.BigEndian.PutUint16(packet[14:16], 64); return packet }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			packet := tt.mutate(append([]byte(nil), valid...))
			_, _, err := ParseV2Datagram(packet)
			require.Error(t, err)
		})
	}
}

func testV2Datagram(source, destination netip.AddrPort, payload []byte) []byte {
	addressLength := 12
	familyProtocol := byte(0x12)
	if source.Addr().Is6() {
		addressLength = 36
		familyProtocol = 0x22
	}

	packet := make([]byte, 16+addressLength+len(payload))
	copy(packet, v2Signature)
	packet[12] = 0x21
	packet[13] = familyProtocol
	binary.BigEndian.PutUint16(packet[14:16], uint16(addressLength))

	if source.Addr().Is4() {
		sourceBytes := source.Addr().As4()
		destinationBytes := destination.Addr().As4()
		copy(packet[16:20], sourceBytes[:])
		copy(packet[20:24], destinationBytes[:])
		binary.BigEndian.PutUint16(packet[24:26], source.Port())
		binary.BigEndian.PutUint16(packet[26:28], destination.Port())
	} else {
		sourceBytes := source.Addr().As16()
		destinationBytes := destination.Addr().As16()
		copy(packet[16:32], sourceBytes[:])
		copy(packet[32:48], destinationBytes[:])
		binary.BigEndian.PutUint16(packet[48:50], source.Port())
		binary.BigEndian.PutUint16(packet[50:52], destination.Port())
	}

	copy(packet[16+addressLength:], payload)

	return packet
}
