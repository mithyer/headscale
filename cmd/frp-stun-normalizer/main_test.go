package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/derp/proxyprotocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizerAddsProxyHeaderToEveryDatagram(t *testing.T) {
	t.Parallel()

	upstream := listenUDP(t)
	listener := listenUDP(t)
	client := listenUDP(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	normalizer := newNormalizer(listener, upstream.LocalAddr().String(), time.Minute, time.Second, 16)
	errCh := make(chan error, 1)
	go func() {
		errCh <- normalizer.serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-errCh)
	})

	originalSource := netip.MustParseAddrPort("198.51.100.10:41641")
	originalDestination := netip.MustParseAddrPort("192.0.2.20:1235")

	firstPayload := []byte("first")
	firstPacket := testV2Datagram(originalSource, originalDestination, firstPayload)
	_, err := client.WriteToUDP(firstPacket, listener.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	firstPeer := assertNormalizedDatagram(t, upstream, originalSource, firstPayload)
	_, err = upstream.WriteToUDP([]byte("first response"), firstPeer)
	require.NoError(t, err)
	assertUDPDatagram(t, client, []byte("first response"))

	secondPayload := []byte("second")
	_, err = client.WriteToUDP(secondPayload, listener.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	secondPeer := assertNormalizedDatagram(t, upstream, originalSource, secondPayload)
	assert.Equal(t, firstPeer.String(), secondPeer.String())
	_, err = upstream.WriteToUDP([]byte("second response"), secondPeer)
	require.NoError(t, err)
	assertUDPDatagram(t, client, []byte("second response"))
}

func TestNormalizerDropsHeaderlessFirstDatagram(t *testing.T) {
	t.Parallel()

	upstream := listenUDP(t)
	listener := listenUDP(t)
	client := listenUDP(t)
	normalizer := newNormalizer(listener, upstream.LocalAddr().String(), time.Minute, time.Second, 16)

	err := normalizer.forwardDatagram([]byte("missing header"), client.LocalAddr().(*net.UDPAddr))
	require.ErrorContains(t, err, "first datagram")
}

func TestNormalizerRetainsExistingSessionAtCapacity(t *testing.T) {
	t.Parallel()

	upstream := listenUDP(t)
	listener := listenUDP(t)
	firstClient := listenUDP(t)
	secondClient := listenUDP(t)
	normalizer := newNormalizer(listener, upstream.LocalAddr().String(), time.Minute, time.Second, 1)

	originalDestination := netip.MustParseAddrPort("192.0.2.20:1235")
	firstSource := netip.MustParseAddrPort("198.51.100.10:41641")
	secondSource := netip.MustParseAddrPort("198.51.100.11:41641")

	err := normalizer.forwardDatagram(
		testV2Datagram(firstSource, originalDestination, []byte("first")),
		firstClient.LocalAddr().(*net.UDPAddr),
	)
	require.NoError(t, err)
	assertNormalizedDatagram(t, upstream, firstSource, []byte("first"))

	err = normalizer.forwardDatagram(
		testV2Datagram(secondSource, originalDestination, []byte("second")),
		secondClient.LocalAddr().(*net.UDPAddr),
	)
	require.ErrorContains(t, err, "session capacity")

	err = normalizer.forwardDatagram([]byte("still active"), firstClient.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	assertNormalizedDatagram(t, upstream, firstSource, []byte("still active"))
}

func TestNormalizerReconnectsUpstreamWithoutLosingIdentity(t *testing.T) {
	t.Parallel()

	upstream := listenUDP(t)
	listener := listenUDP(t)
	client := listenUDP(t)
	normalizer := newNormalizer(listener, upstream.LocalAddr().String(), time.Minute, 50*time.Millisecond, 16)

	originalSource := netip.MustParseAddrPort("198.51.100.10:41641")
	originalDestination := netip.MustParseAddrPort("192.0.2.20:1235")
	err := normalizer.forwardDatagram(
		testV2Datagram(originalSource, originalDestination, []byte("first")),
		client.LocalAddr().(*net.UDPAddr),
	)
	require.NoError(t, err)
	assertNormalizedDatagram(t, upstream, originalSource, []byte("first"))

	time.Sleep(100 * time.Millisecond)

	err = normalizer.forwardDatagram([]byte("after timeout"), client.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	peer := assertNormalizedDatagram(t, upstream, originalSource, []byte("after timeout"))
	_, err = upstream.WriteToUDP([]byte("reconnected response"), peer)
	require.NoError(t, err)
	assertUDPDatagram(t, client, []byte("reconnected response"))
}

func TestSignalReady(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "normalizer.ready")
	require.NoError(t, signalReady(path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.ErrorContains(t, signalReady(path), "creating readiness file")
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return conn
}

func assertNormalizedDatagram(
	t *testing.T,
	upstream *net.UDPConn,
	wantSource netip.AddrPort,
	wantPayload []byte,
) *net.UDPAddr {
	t.Helper()

	require.NoError(t, upstream.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, packetBufferSize)
	bytesRead, peer, err := upstream.ReadFromUDP(buf)
	require.NoError(t, err)
	header, payload, err := proxyprotocol.ParseV2Datagram(buf[:bytesRead])
	require.NoError(t, err)
	assert.Equal(t, wantSource, header.Source)
	assert.Equal(t, wantPayload, payload)

	return peer
}

func assertUDPDatagram(t *testing.T, conn *net.UDPConn, want []byte) {
	t.Helper()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, packetBufferSize)
	bytesRead, _, err := conn.ReadFromUDP(buf)
	require.NoError(t, err)
	assert.Equal(t, want, buf[:bytesRead])
}

func testV2Datagram(source, destination netip.AddrPort, payload []byte) []byte {
	addressLength := 12
	familyProtocol := byte(0x12)
	if source.Addr().Is6() {
		addressLength = 36
		familyProtocol = 0x22
	}

	packet := make([]byte, 16+addressLength+len(payload))
	copy(packet, []byte("\r\n\r\n\x00\r\nQUIT\n"))
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
