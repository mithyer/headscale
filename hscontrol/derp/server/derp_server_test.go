package server

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/stun"
)

func TestSTUNListenerProxyProtocolV2(t *testing.T) {
	t.Parallel()

	serverConn := listenTestUDP(t)
	clientConn := listenTestUDP(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		serverSTUNListener(ctx, serverConn, true)
	}()
	t.Cleanup(func() {
		cancel()
		_ = serverConn.Close()
		<-done
	})

	txID := stun.NewTxID()
	originalSource := netip.MustParseAddrPort("198.51.100.10:41641")
	originalDestination := netip.MustParseAddrPort("192.0.2.20:1235")
	request := testProxyV2Datagram(originalSource, originalDestination, stun.Request(txID))

	_, err := clientConn.WriteToUDP(request, serverConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(2*time.Second)))

	buf := make([]byte, 1500)
	bytesRead, _, err := clientConn.ReadFromUDP(buf)
	require.NoError(t, err)
	responseTxID, mappedAddr, err := stun.ParseResponse(buf[:bytesRead])
	require.NoError(t, err)
	assert.Equal(t, txID, responseTxID)
	assert.Equal(t, originalSource, mappedAddr)
}

func TestSTUNListenerWithoutProxyProtocol(t *testing.T) {
	t.Parallel()

	serverConn := listenTestUDP(t)
	clientConn := listenTestUDP(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		serverSTUNListener(ctx, serverConn, false)
	}()
	t.Cleanup(func() {
		cancel()
		_ = serverConn.Close()
		<-done
	})

	txID := stun.NewTxID()
	_, err := clientConn.WriteToUDP(stun.Request(txID), serverConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(2*time.Second)))

	buf := make([]byte, 1500)
	bytesRead, _, err := clientConn.ReadFromUDP(buf)
	require.NoError(t, err)
	responseTxID, mappedAddr, err := stun.ParseResponse(buf[:bytesRead])
	require.NoError(t, err)
	assert.Equal(t, txID, responseTxID)
	assert.Equal(t, clientConn.LocalAddr().(*net.UDPAddr).AddrPort(), mappedAddr)
}

func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return conn
}

func testProxyV2Datagram(source, destination netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	copy(packet, []byte("\r\n\r\n\x00\r\nQUIT\n"))
	packet[12] = 0x21
	packet[13] = 0x12
	binary.BigEndian.PutUint16(packet[14:16], 12)
	sourceBytes := source.Addr().As4()
	destinationBytes := destination.Addr().As4()
	copy(packet[16:20], sourceBytes[:])
	copy(packet[20:24], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[24:26], source.Port())
	binary.BigEndian.PutUint16(packet[26:28], destination.Port())
	copy(packet[28:], payload)

	return packet
}
