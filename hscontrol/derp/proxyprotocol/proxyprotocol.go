package proxyprotocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const headerPrefixLength = 16

var (
	v2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

	errHeaderTooShort       = errors.New("PROXY protocol v2 header is too short")
	errInvalidSignature     = errors.New("invalid PROXY protocol v2 signature")
	errInvalidVersion       = errors.New("invalid PROXY protocol version")
	errUnsupportedCommand   = errors.New("unsupported PROXY protocol command")
	errUnsupportedTransport = errors.New("PROXY protocol transport is not UDP")
	errUnsupportedFamily    = errors.New("unsupported PROXY protocol address family")
	errInvalidLength        = errors.New("invalid PROXY protocol v2 address length")
)

// Header contains the UDP addresses carried by a PROXY protocol v2 datagram.
type Header struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	Length      int
}

// HasV2Signature reports whether packet starts with the PROXY protocol v2
// signature. It does not validate the rest of the header.
func HasV2Signature(packet []byte) bool {
	return len(packet) >= len(v2Signature) && bytes.Equal(packet[:len(v2Signature)], v2Signature)
}

// ParseV2Datagram parses a PROXY protocol v2 UDP header and returns the
// original payload without copying it.
func ParseV2Datagram(packet []byte) (Header, []byte, error) {
	if len(packet) < headerPrefixLength {
		return Header{}, nil, errHeaderTooShort
	}
	if !HasV2Signature(packet) {
		return Header{}, nil, errInvalidSignature
	}

	versionCommand := packet[12]
	if versionCommand>>4 != 2 {
		return Header{}, nil, errInvalidVersion
	}
	if versionCommand&0x0f != 1 {
		return Header{}, nil, errUnsupportedCommand
	}

	familyProtocol := packet[13]
	if familyProtocol&0x0f != 2 {
		return Header{}, nil, errUnsupportedTransport
	}

	addressLength := int(binary.BigEndian.Uint16(packet[14:16]))
	headerLength := headerPrefixLength + addressLength
	if headerLength > len(packet) {
		return Header{}, nil, fmt.Errorf("%w: header declares %d bytes, datagram has %d", errInvalidLength, headerLength, len(packet))
	}

	var source, destination netip.AddrPort
	switch familyProtocol >> 4 {
	case 1:
		if addressLength < 12 {
			return Header{}, nil, fmt.Errorf("%w: IPv4 address block is %d bytes", errInvalidLength, addressLength)
		}

		source = netip.AddrPortFrom(
			netip.AddrFrom4([4]byte(packet[16:20])),
			binary.BigEndian.Uint16(packet[24:26]),
		)
		destination = netip.AddrPortFrom(
			netip.AddrFrom4([4]byte(packet[20:24])),
			binary.BigEndian.Uint16(packet[26:28]),
		)
	case 2:
		if addressLength < 36 {
			return Header{}, nil, fmt.Errorf("%w: IPv6 address block is %d bytes", errInvalidLength, addressLength)
		}

		source = netip.AddrPortFrom(
			netip.AddrFrom16([16]byte(packet[16:32])),
			binary.BigEndian.Uint16(packet[48:50]),
		)
		destination = netip.AddrPortFrom(
			netip.AddrFrom16([16]byte(packet[32:48])),
			binary.BigEndian.Uint16(packet[50:52]),
		)
	default:
		return Header{}, nil, errUnsupportedFamily
	}

	return Header{
		Source:      source,
		Destination: destination,
		Length:      headerLength,
	}, packet[headerLength:], nil
}
