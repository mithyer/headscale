package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/juanfont/headscale/hscontrol/derp/proxyprotocol"
)

const packetBufferSize = 64 << 10

type session struct {
	peer       *net.UDPAddr
	header     []byte
	upstream   *net.UDPConn
	lastActive time.Time
}

type normalizer struct {
	listener     *net.UDPConn
	upstreamAddr string
	idleTimeout  time.Duration
	responseWait time.Duration
	maxSessions  int

	mu       sync.Mutex
	sessions map[netip.AddrPort]*session
}

func newNormalizer(
	listener *net.UDPConn,
	upstreamAddr string,
	idleTimeout time.Duration,
	responseWait time.Duration,
	maxSessions int,
) *normalizer {
	return &normalizer{
		listener:     listener,
		upstreamAddr: upstreamAddr,
		idleTimeout:  idleTimeout,
		responseWait: responseWait,
		maxSessions:  maxSessions,
		sessions:     make(map[netip.AddrPort]*session),
	}
}

func (n *normalizer) serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = n.listener.Close()
	}()
	go n.cleanupLoop(ctx)

	buf := make([]byte, packetBufferSize)
	for {
		bytesRead, peer, err := n.listener.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				n.closeSessions()

				return nil
			}

			return fmt.Errorf("reading UDP datagram: %w", err)
		}

		packet := append([]byte(nil), buf[:bytesRead]...)
		if err := n.forwardDatagram(packet, peer); err != nil {
			log.Printf("dropping UDP datagram from %s: %v", peer, err)
		}
	}
}

func (n *normalizer) forwardDatagram(packet []byte, peer *net.UDPAddr) error {
	key := peer.AddrPort()
	payload := packet

	n.mu.Lock()
	defer n.mu.Unlock()

	sess := n.sessions[key]
	if proxyprotocol.HasV2Signature(packet) {
		header, proxyPayload, err := proxyprotocol.ParseV2Datagram(packet)
		if err != nil {
			return err
		}

		payload = proxyPayload
		if sess == nil {
			var err error
			sess, err = n.createSessionLocked(peer, time.Now())
			if err != nil {
				return err
			}
			n.sessions[key] = sess
		}
		sess.header = append(sess.header[:0], packet[:header.Length]...)
	} else if sess == nil {
		return errors.New("first datagram for FRP UDP session has no PROXY protocol v2 header")
	}

	sess.lastActive = time.Now()
	normalized := make([]byte, 0, len(sess.header)+len(payload))
	normalized = append(normalized, sess.header...)
	normalized = append(normalized, payload...)

	var lastErr error
	for range 2 {
		upstream, err := n.ensureUpstreamLocked(key, sess)
		if err != nil {
			lastErr = err

			continue
		}
		if err := upstream.SetReadDeadline(time.Now().Add(n.responseWait)); err != nil {
			n.closeUpstreamLocked(sess, upstream)
			lastErr = err

			continue
		}
		if _, err := upstream.Write(normalized); err != nil {
			n.closeUpstreamLocked(sess, upstream)
			lastErr = err

			continue
		}

		return nil
	}

	return fmt.Errorf("writing normalized datagram upstream: %w", lastErr)
}

func (n *normalizer) createSessionLocked(peer *net.UDPAddr, now time.Time) (*session, error) {
	n.removeExpiredSessionsLocked(now)
	if len(n.sessions) >= n.maxSessions {
		return nil, fmt.Errorf("session capacity reached (%d)", n.maxSessions)
	}

	return &session{
		peer:       cloneUDPAddr(peer),
		lastActive: now,
	}, nil
}

func (n *normalizer) ensureUpstreamLocked(
	key netip.AddrPort,
	sess *session,
) (*net.UDPConn, error) {
	if sess.upstream != nil {
		return sess.upstream, nil
	}

	upstreamAddr, err := net.ResolveUDPAddr("udp", n.upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("resolving upstream address: %w", err)
	}
	upstream, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("opening upstream UDP session: %w", err)
	}
	sess.upstream = upstream
	go n.relayResponses(key, sess, upstream)

	return upstream, nil
}

func (n *normalizer) relayResponses(
	key netip.AddrPort,
	sess *session,
	upstream *net.UDPConn,
) {
	buf := make([]byte, packetBufferSize)
	for {
		bytesRead, err := upstream.Read(buf)
		if err != nil {
			n.mu.Lock()
			if n.sessions[key] == sess {
				n.closeUpstreamLocked(sess, upstream)
			}
			n.mu.Unlock()

			return
		}

		if _, err := n.listener.WriteToUDP(buf[:bytesRead], sess.peer); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("forwarding UDP response to %s: %v", sess.peer, err)
			}
			n.mu.Lock()
			if n.sessions[key] == sess {
				n.closeUpstreamLocked(sess, upstream)
			}
			n.mu.Unlock()

			return
		}

		n.mu.Lock()
		if n.sessions[key] == sess {
			sess.lastActive = time.Now()
		}
		n.mu.Unlock()
	}
}

func (n *normalizer) cleanupLoop(ctx context.Context) {
	interval := min(n.idleTimeout/2, 30*time.Second)
	if interval <= 0 {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			n.mu.Lock()
			n.removeExpiredSessionsLocked(now)
			n.mu.Unlock()
		}
	}
}

func (n *normalizer) removeExpiredSessionsLocked(now time.Time) {
	for key, sess := range n.sessions {
		if now.Sub(sess.lastActive) >= n.idleTimeout {
			n.removeSessionLocked(key, sess)
		}
	}
}

func (n *normalizer) removeSessionLocked(key netip.AddrPort, sess *session) {
	if n.sessions[key] != sess {
		return
	}

	delete(n.sessions, key)
	if sess.upstream != nil {
		_ = sess.upstream.Close()
		sess.upstream = nil
	}
}

func (*normalizer) closeUpstreamLocked(sess *session, upstream *net.UDPConn) {
	if sess.upstream != upstream {
		return
	}

	_ = upstream.Close()
	sess.upstream = nil
}

func (n *normalizer) closeSessions() {
	n.mu.Lock()
	defer n.mu.Unlock()

	for key, sess := range n.sessions {
		n.removeSessionLocked(key, sess)
	}
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func signalReady(path string) error {
	if path == "" {
		return nil
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating readiness file: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("closing readiness file: %w", err)
	}

	return nil
}

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:1235", "UDP address receiving FRP datagrams")
	upstreamAddr := flag.String("upstream", "127.0.0.1:3478", "Headscale STUN UDP address")
	idleTimeout := flag.Duration("idle-timeout", 2*time.Minute, "idle FRP session lifetime")
	responseWait := flag.Duration("response-timeout", 5*time.Second, "maximum wait for an upstream STUN response")
	maxSessions := flag.Int("max-sessions", 1024, "maximum simultaneous FRP UDP sessions")
	readyFile := flag.String("ready-file", "", "create this file after binding the UDP listener")
	flag.Parse()

	if *idleTimeout <= 30*time.Second {
		log.Fatal("idle-timeout must be greater than FRP's 30 second UDP session timeout")
	}
	if *maxSessions <= 0 {
		log.Fatal("max-sessions must be positive")
	}
	if *responseWait <= 0 {
		log.Fatal("response-timeout must be positive")
	}

	listenUDPAddr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		log.Fatalf("resolving listen address: %v", err)
	}
	listener, err := net.ListenUDP("udp", listenUDPAddr)
	if err != nil {
		log.Fatalf("opening UDP listener: %v", err)
	}
	if err := signalReady(*readyFile); err != nil {
		_ = listener.Close()
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("normalizing FRP UDP PROXY v2 datagrams on %s to %s", listener.LocalAddr(), *upstreamAddr)
	if err := newNormalizer(listener, *upstreamAddr, *idleTimeout, *responseWait, *maxSessions).serve(ctx); err != nil {
		log.Fatal(err)
	}
}
