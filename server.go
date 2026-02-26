package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Constants matching the C implementation
const (
	bufSize                  = 16384
	httpRequestTimeout       = 30 * time.Second
	tunnelRecvTimeout        = 5 * time.Second
	maxConnections           = 256
	connectTimeout           = 15 * time.Second
	piggybackCoalesceTimeout = 5 * time.Millisecond
)

func protoName(isSocks5 bool) string {
	if isSocks5 {
		return "SOCKS5"
	}
	return "HTTP"
}

// Shared TLS config with session cache, initialized once via initTLSConfig.
var tlsConfig *tls.Config

// initTLSConfig creates the shared TLS config with session resumption.
// Must be called once after the relay host is known.
func initTLSConfig(host string) {
	tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}
	if net.ParseIP(host) == nil {
		tlsConfig.ServerName = host
		logDebug("TLS config: SNI hostname %s, session cache enabled", host)
	} else {
		logDebug("TLS config: no SNI (IP address), session cache enabled")
	}
}

// dialRelay connects to the relay server via TCP+TLS.
func dialRelay(ctx context.Context, host string, port uint16) (*tls.Conn, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// TCP connect with timeout
	dialer := net.Dialer{
		Timeout: connectTimeout,
	}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP connect to %s: %w", addr, err)
	}

	// Set keepalive on TCP connection
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	// TCP_NODELAY is enabled by default in Go's net package.

	logDebug("TCP connected to %s", addr)

	// TLS handshake using shared config with session cache
	tlsConn := tls.Client(tcpConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", addr, err)
	}

	state := tlsConn.ConnectionState()
	resumeStr := "full handshake"
	if state.DidResume {
		resumeStr = "resumed"
	}
	logInfo("TLS connected to %s [%s, %s, %s]", addr,
		tlsVersionString(state.Version),
		tls.CipherSuiteName(state.CipherSuite),
		resumeStr)

	return tlsConn, nil
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("TLS(0x%04x)", v)
	}
}

// runServer starts the proxy server and blocks until ctx is cancelled.
func runServer(ctx context.Context) error {
	addr := net.JoinHostPort(gConfig.listenHost, fmt.Sprintf("%d", gConfig.listenPort))

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	// Close listener when context is cancelled to unblock Accept
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	protoStr := "auto"
	if gConfig.listenProto == listenProtoHTTP {
		protoStr = "http"
	} else if gConfig.listenProto == listenProtoSOCKS5 {
		protoStr = "socks5"
	}

	logInfo("Listening on %s (protocol: %s)", addr, protoStr)

	authInfo := ""
	if gConfig.username != "" {
		authInfo = gConfig.username + ":***@"
	}
	logInfo("Relay: relay+tls://%s%s:%d", authInfo, gConfig.relayHost, gConfig.relayPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check if we're shutting down
			select {
			case <-ctx.Done():
				logDebug("Shutdown requested, exiting accept loop")
				return nil
			default:
			}
			logError("accept failed: %v", err)
			continue
		}

		// Check connection limit
		if atomicLoadConnections() >= maxConnections {
			logDebug("Max connections (%d) reached, rejecting", maxConnections)
			conn.Close()
			continue
		}

		// Get client IP
		clientIP := "unknown"
		if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			clientIP = addr.IP.String()
		}

		logDebug("Connection from %s", clientIP)

		go handleConnection(ctx, conn, clientIP)
	}
}

// handleConnection handles a single client connection.
func handleConnection(ctx context.Context, clientConn net.Conn, clientIP string) {
	atomicAddConnections(1)
	defer func() {
		clientConn.Close()
		atomicAddConnections(-1)
	}()

	// Auto-detect or use configured protocol
	var isSocks5 bool
	br := bufio.NewReaderSize(clientConn, bufSize)

	switch gConfig.listenProto {
	case listenProtoSOCKS5:
		isSocks5 = true
	case listenProtoHTTP:
		isSocks5 = false
	default:
		// Auto-detect: peek first byte
		first, err := br.Peek(1)
		if err != nil {
			logDebug("Client %s: closed before sending data", clientIP)
			return
		}
		isSocks5 = (first[0] == socks5Ver)
		logDebug("Auto-detected protocol: %s (first byte 0x%02x)",
			protoName(isSocks5), first[0])
	}

	// Read and parse client request
	var targetHost string
	var targetPort uint16
	var trailData []byte

	if isSocks5 {
		req, err := readSocks5Request(clientConn, br)
		if err != nil {
			logDebug("Client %s: SOCKS5 request failed: %v", clientIP, err)
			return
		}
		targetHost = req.host
		targetPort = req.port
	} else {
		req, err := readConnectRequest(clientConn, br)
		if err != nil {
			logDebug("Client %s: HTTP request failed: %v", clientIP, err)
			clientConn.Write([]byte(httpResp400))
			return
		}
		targetHost = req.host
		targetPort = req.port
		trailData = req.trailData
	}

	logInfo("Client %s: CONNECT %s:%d (%s)", clientIP, targetHost, targetPort,
		protoName(isSocks5))

	// Encode relay CONNECT request (before connecting, no dependency on relay)
	var relayReq [512]byte
	relayReqLen, err := relayEncodeRequest(relayReq[:], targetHost, targetPort,
		gConfig.username, gConfig.password)
	if err != nil {
		logError("Failed to encode relay request: %v", err)
		sendClientError(clientConn, isSocks5)
		return
	}

	// Connect to relay first — if it fails, tell the client before they send data.
	relayConn, err := dialRelay(ctx, gConfig.relayHost, gConfig.relayPort)
	if err != nil {
		logError("Failed to connect to relay %s:%d: %v",
			gConfig.relayHost, gConfig.relayPort, err)
		sendClientError(clientConn, isSocks5)
		return
	}

	// Send success response to client (relay is connected)
	if isSocks5 {
		if err := socks5SendReply(clientConn, socks5RepOK); err != nil {
			logError("Failed to send SOCKS5 reply to client")
			relayConn.Close()
			return
		}
	} else {
		if _, err := clientConn.Write([]byte(httpResp200)); err != nil {
			logError("Failed to send HTTP 200 to client")
			relayConn.Close()
			return
		}
	}

	// Run bidirectional tunnel with piggybacking.
	// For HTTP: trailData contains data after \r\n\r\n (may be empty).
	// For SOCKS5: trailData is nil, runTunnel will wait for first client data.
	runTunnel(ctx, clientConn, br, relayConn,
		relayReq[:relayReqLen], trailData,
		clientIP, targetHost, targetPort)
}

// sendClientError sends an error back to the client using the appropriate protocol.
func sendClientError(conn net.Conn, isSocks5 bool) {
	if isSocks5 {
		socks5SendReply(conn, socks5RepGeneral)
	} else {
		conn.Write([]byte(httpResp503))
	}
}

// runTunnel copies data bidirectionally between clientConn and relayConn.
// It takes ownership of relayConn and closes it before returning.
//
// relay flow:
// 1. Send relay request + trail data (combined)
// 2. Drain additional immediately available client data and send to relay
// 3. Read relay response sequentially (after all initial data sent)
// 4. Start bidirectional copy loop
func runTunnel(ctx context.Context, clientConn net.Conn, clientReader io.Reader,
	relayConn net.Conn, relayReq []byte, trailData []byte,
	clientIP, host string, port uint16) {

	logInfo("Tunnel established: %s -> %s:%d", clientIP, host, port)

	// Phase 1 — Send relay request piggybacked with trail data (if any),
	// then wait for first client data and drain immediately available data.
	// Send everything to relay before waiting for relay response.

	if len(trailData) > 0 {
		// Have trail data (HTTP CONNECT with data after headers)
		combined := make([]byte, len(relayReq)+len(trailData))
		copy(combined, relayReq)
		copy(combined[len(relayReq):], trailData)
		logDebug("Relay handshake: sending %d bytes (header %d + trail %d)",
			len(combined), len(relayReq), len(trailData))
		if _, err := relayConn.Write(combined); err != nil {
			logDebug("Client->Relay: relay write error (trail): %v", err)
			relayConn.Close()
			return
		}
	} else {
		// No trail data — just send relay request header
		logDebug("Relay handshake: sending %d bytes (header only)", len(relayReq))
		if _, err := relayConn.Write(relayReq); err != nil {
			logDebug("Client->Relay: relay write error (header): %v", err)
			relayConn.Close()
			return
		}
	}

	// Drain all remaining immediately available client data and send to relay
	// Use a short deadline to only send data that's already available
	clientConn.SetReadDeadline(time.Now().Add(piggybackCoalesceTimeout))
	n, _ := io.Copy(relayConn, clientReader)
	clientConn.SetReadDeadline(time.Time{})
	if n > 0 {
		logDebug("Relay handshake: sent additional %d bytes", n)
	}

	// Phase 2 — Read relay response synchronously (after all client data sent)
	status, err := relayReadResponse(relayConn)
	if err != nil {
		logError("Failed to read relay response: %v", err)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		relayConn.Close()
		return
	}
	if status != relayStatusOK {
		logError("Relay error: %s (0x%02x)", relayStatusString(status), status)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		relayConn.Close()
		return
	}

	// Phase 3 — Bidirectional copy loop (goroutines for concurrent copy)
	var wg sync.WaitGroup

	// relay -> client
	wg.Go(func() {
		io.Copy(clientConn, relayConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	})

	// client -> relay
	{
		shutdownDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				clientConn.SetReadDeadline(time.Now())
			case <-shutdownDone:
			}
		}()
		io.Copy(relayConn, clientReader)
		close(shutdownDone)
	}

	// Half-close the TLS write side
	if tc, ok := relayConn.(*tls.Conn); ok {
		tc.CloseWrite()
	}
	relayConn.SetReadDeadline(time.Now().Add(tunnelRecvTimeout))
	wg.Wait()
	relayConn.Close()

	logInfo("Tunnel closed: %s -> %s:%d", clientIP, host, port)
}
