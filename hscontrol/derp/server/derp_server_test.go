package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/envknob"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
)

// TestSTUNListenerProxyProtocolV2 verifies that the listener reports the
// original client address from a PROXY protocol v2 UDP datagram.
// TEST:hscontrol/derp/server/derp_server_test.go[TestSTUNListenerProxyProtocolV2]
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

// TestSTUNListenerWithoutProxyProtocol verifies that a direct STUN datagram
// continues to report the actual UDP peer address when proxy parsing is off.
// TEST:hscontrol/derp/server/derp_server_test.go[TestSTUNListenerWithoutProxyProtocol]
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

// listenTestUDP creates a loopback UDP socket for the STUN listener tests.
func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return conn
}

// testProxyV2Datagram builds an IPv4 PROXY protocol v2 datagram containing a
// STUN payload and the supplied source and destination addresses.
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

// TestGenerateRegionInsecureTLS pins the contract nix/testkit.nix relies on:
// with the knob set, the embedded node advertises the TLS listener's port and
// InsecureForTests, so clients without the self-signed cert can relay.
func TestGenerateRegionInsecureTLS(t *testing.T) {
	tests := []struct {
		name         string
		knob         string
		wantPort     int
		wantInsecure bool
		wantErr      bool
	}{
		{name: "unset keeps server_url port", knob: "", wantPort: 80},
		{name: "set advertises TLS port", knob: "[::]:443", wantPort: 443, wantInsecure: true},
		{name: "named port", knob: ":https", wantPort: 443, wantInsecure: true},
		{name: "random port is refused", knob: ":0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envknob.Setenv("HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR", tt.knob)
			t.Cleanup(func() { envknob.Setenv("HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR", "") })

			d := &DERPServer{
				serverURL: "http://headscale",
				cfg: &types.DERPConfig{
					ServerRegionID:   999,
					ServerRegionCode: "headscale",
					STUNAddr:         "[::]:3478",
				},
			}

			region, err := d.GenerateRegion()
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Len(t, region.Nodes, 1)

			node := region.Nodes[0]
			assert.Equal(t, "headscale", node.HostName)
			assert.Equal(t, tt.wantPort, node.DERPPort)
			assert.Equal(t, tt.wantInsecure, node.InsecureForTests)
			assert.Equal(t, 3478, node.STUNPort)
		})
	}
}

// TestDERPBootstrapDNSHandlerFollowsDERPMapUpdates guards against the handler
// resolving a DERP map captured at startup: hostnames that a later
// auto-update adds must be served.
func TestDERPBootstrapDNSHandlerFollowsDERPMapUpdates(t *testing.T) {
	var current atomic.Pointer[tailcfg.DERPMap]
	current.Store(&tailcfg.DERPMap{})

	handler := DERPBootstrapDNSHandler(func() tailcfg.DERPMapView {
		return current.Load().View()
	})

	current.Store(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: {RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "1a", RegionID: 1, HostName: "localhost"}}},
	}})

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/bootstrap-dns", nil))

	var got map[string][]net.IP
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.Contains(t, got, "localhost")
}
