package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Relay protocol constants
const (
	relayVersion    = 0x01
	relayCmdConnect = 0x01
)

// Relay status codes
const (
	relayStatusOK                 = 0x00
	relayStatusBadRequest         = 0x01
	relayStatusUnauthorized       = 0x02
	relayStatusForbidden          = 0x03
	relayStatusTimeout            = 0x04
	relayStatusServiceUnavailable = 0x05
	relayStatusHostUnreachable    = 0x06
	relayStatusNetworkUnreachable = 0x07
	relayStatusInternalError      = 0x08
)

// Relay feature types
const (
	relayFeatUserAuth = 0x01
	relayFeatAddr     = 0x02
)

// Address types (SOCKS5 compatible)
const (
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIPv6   = 0x04
)

// SOCKS5 protocol constants (RFC 1928)
const (
	socks5Ver               = 0x05
	socks5CmdConnect        = 0x01
	socks5AuthNone          = 0x00
	socks5AuthNoAccept      = 0xFF
	socks5RepOK             = 0x00
	socks5RepGeneral        = 0x01
	socks5RepCmdUnsupported = 0x07
)

// Listen protocol modes
const (
	listenProtoHTTP   = 0
	listenProtoSOCKS5 = 1
	listenProtoAuto   = 2
)

// HTTP response strings
const (
	httpResp200 = "HTTP/1.1 200 Connection Established\r\n\r\n"
	httpResp400 = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
	httpResp503 = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
)

// addrType returns the relay address type for the given host string.
func addrType(host string) byte {
	ip := net.ParseIP(host)
	if ip == nil {
		return addrTypeDomain
	}
	if ip.To4() != nil {
		return addrTypeIPv4
	}
	return addrTypeIPv6
}

// relayEncodeRequest encodes a relay CONNECT request into buf.
// Returns the number of bytes written.
//
// Wire format:
//
//	Header: VER(1) + CMD(1) + FEALEN(2)
//	UserAuthFeature (if auth): TYPE(1) + LEN(2) + ULEN(1) + USER + PLEN(1) + PASS
//	AddrFeature: TYPE(1) + LEN(2) + ATYP(1) + ADDR + PORT(2)
func relayEncodeRequest(buf []byte, host string, port uint16, username, password string) (int, error) {
	if len(buf) < 32 {
		return 0, fmt.Errorf("buffer too small")
	}

	p := 4 // skip header (VER+CMD+FEALEN)
	featStart := p

	// UserAuthFeature
	if username != "" {
		ulen := len(username)
		plen := len(password)
		if ulen > 255 {
			ulen = 255
		}
		if plen > 255 {
			plen = 255
		}
		featDataLen := 1 + ulen + 1 + plen
		if p+3+featDataLen > len(buf) {
			return 0, fmt.Errorf("buffer too small for auth")
		}
		buf[p] = relayFeatUserAuth
		p++
		binary.BigEndian.PutUint16(buf[p:], uint16(featDataLen))
		p += 2
		buf[p] = byte(ulen)
		p++
		copy(buf[p:], username[:ulen])
		p += ulen
		buf[p] = byte(plen)
		p++
		if plen > 0 {
			copy(buf[p:], password[:plen])
			p += plen
		}
	}

	// AddrFeature
	atyp := addrType(host)
	var addrDataLen int
	switch atyp {
	case addrTypeIPv4:
		addrDataLen = 1 + 4 + 2
	case addrTypeIPv6:
		addrDataLen = 1 + 16 + 2
	default:
		addrDataLen = 1 + 1 + len(host) + 2
	}

	if p+3+addrDataLen > len(buf) {
		return 0, fmt.Errorf("buffer too small for addr")
	}

	buf[p] = relayFeatAddr
	p++
	binary.BigEndian.PutUint16(buf[p:], uint16(addrDataLen))
	p += 2
	buf[p] = atyp
	p++

	switch atyp {
	case addrTypeIPv4:
		ip := net.ParseIP(host).To4()
		copy(buf[p:], ip)
		p += 4
	case addrTypeIPv6:
		ip := net.ParseIP(host).To16()
		copy(buf[p:], ip)
		p += 16
	default:
		if len(host) > 255 {
			return 0, fmt.Errorf("domain name too long: %d", len(host))
		}
		buf[p] = byte(len(host))
		p++
		copy(buf[p:], host)
		p += len(host)
	}

	binary.BigEndian.PutUint16(buf[p:], port)
	p += 2

	// Fill in header
	featLen := p - featStart
	buf[0] = relayVersion
	buf[1] = relayCmdConnect
	binary.BigEndian.PutUint16(buf[2:], uint16(featLen))

	return p, nil
}

// relayReadResponse reads a relay response from r.
// Returns the status byte.
func relayReadResponse(r io.Reader) (byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, fmt.Errorf("read relay response header: %w", err)
	}

	if hdr[0] != relayVersion {
		return 0, fmt.Errorf("invalid relay version: 0x%02x (expected 0x%02x)", hdr[0], relayVersion)
	}

	status := hdr[1]
	feaLen := binary.BigEndian.Uint16(hdr[2:])

	logDebug("Relay response: status=0x%02x (%s), fea_len=%d", status, relayStatusString(status), feaLen)

	// Discard features
	if feaLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(feaLen)); err != nil {
			return 0, fmt.Errorf("read relay features: %w", err)
		}
	}

	return status, nil
}

// relayStatusString returns a human-readable string for the relay status code.
func relayStatusString(status byte) string {
	switch status {
	case relayStatusOK:
		return "OK"
	case relayStatusBadRequest:
		return "Bad Request"
	case relayStatusUnauthorized:
		return "Unauthorized"
	case relayStatusForbidden:
		return "Forbidden"
	case relayStatusTimeout:
		return "Timeout"
	case relayStatusServiceUnavailable:
		return "Service Unavailable"
	case relayStatusHostUnreachable:
		return "Host Unreachable"
	case relayStatusNetworkUnreachable:
		return "Network Unreachable"
	case relayStatusInternalError:
		return "Internal Error"
	default:
		return "Unknown"
	}
}

// HTTP CONNECT protocol handling

type connectRequest struct {
	host      string
	port      uint16
	trailData []byte // data after \r\n\r\n
}

// readConnectRequest reads an HTTP CONNECT request from the client connection.
// It uses the provided bufio.Reader (which may have buffered data from auto-detect peek).
func readConnectRequest(conn net.Conn, br *bufio.Reader) (*connectRequest, error) {
	conn.SetReadDeadline(time.Now().Add(httpRequestTimeout))
	defer conn.SetReadDeadline(time.Time{})

	// Read until \r\n\r\n. Only scan new data for the delimiter to avoid O(n^2).
	var accumulated []byte
	buf := make([]byte, bufSize)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			prevLen := len(accumulated)
			accumulated = append(accumulated, buf[:n]...)
			// Scan from where new data could form the delimiter (back up 3 bytes
			// in case \r\n\r\n straddles the boundary of old and new data).
			searchFrom := max(prevLen-3, 0)
			if idx := bytes.Index(accumulated[searchFrom:], []byte("\r\n\r\n")); idx >= 0 {
				headerEnd := searchFrom + idx + 4
				var trail []byte
				if headerEnd < len(accumulated) {
					trail = make([]byte, len(accumulated)-headerEnd)
					copy(trail, accumulated[headerEnd:])
				}
				return parseConnectHeaders(accumulated[:headerEnd], trail)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("reading HTTP request: %w", err)
		}
		if len(accumulated) > bufSize {
			return nil, fmt.Errorf("HTTP headers too large")
		}
	}
}

// parseConnectHeaders parses "CONNECT host:port HTTP/1.x\r\n..." headers.
func parseConnectHeaders(headers []byte, trailData []byte) (*connectRequest, error) {
	// Find first line
	before, _, ok := bytes.Cut(headers, []byte{'\r'})
	if !ok {
		return nil, fmt.Errorf("malformed HTTP request line")
	}
	line := string(before)

	// Parse "CONNECT host:port HTTP/1.x"
	if !strings.HasPrefix(line, "CONNECT ") {
		sp := strings.IndexByte(line, ' ')
		if sp > 0 {
			return nil, fmt.Errorf("unsupported method: %s (only CONNECT is supported)", line[:sp])
		}
		return nil, fmt.Errorf("malformed HTTP request line")
	}

	rest := line[8:] // after "CONNECT "
	target, _, ok := strings.Cut(rest, " ")
	if !ok {
		return nil, fmt.Errorf("malformed CONNECT request line")
	}
	if target == "" {
		return nil, fmt.Errorf("CONNECT target is empty")
	}

	host, portStr, err := parseHostPort(target)
	if err != nil {
		return nil, err
	}

	var port uint16
	if portStr != "" {
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		port = uint16(p)
	} else {
		port = 443
	}

	logDebug("Parsed CONNECT target: %s:%d", host, port)

	req := &connectRequest{
		host: host,
		port: port,
	}
	if len(trailData) > 0 {
		req.trailData = trailData
	}
	return req, nil
}

// parseHostPort splits "host:port" or "[ipv6]:port" into host and port strings.
// If no port is present, portStr is empty.
func parseHostPort(target string) (host, portStr string, err error) {
	if len(target) > 0 && target[0] == '[' {
		// Bracketed IPv6: [::1]:port
		bracket := strings.IndexByte(target, ']')
		if bracket < 0 {
			return "", "", fmt.Errorf("invalid IPv6 address: missing ]")
		}
		host = target[1:bracket]
		rest := target[bracket+1:]
		if len(rest) > 0 && rest[0] == ':' {
			portStr = rest[1:]
		}
		return host, portStr, nil
	}

	colon := strings.LastIndexByte(target, ':')
	if colon >= 0 {
		host = target[:colon]
		portStr = target[colon+1:]
	} else {
		host = target
	}
	return host, portStr, nil
}

// SOCKS5 protocol handling

type socks5Request struct {
	host string
	port uint16
}

// readSocks5Request reads and parses a SOCKS5 CONNECT request.
// Handles the two-phase RFC 1928 handshake.
func readSocks5Request(conn net.Conn, br *bufio.Reader) (*socks5Request, error) {
	conn.SetReadDeadline(time.Now().Add(httpRequestTimeout))
	defer conn.SetReadDeadline(time.Time{})

	// Phase 1: Method negotiation
	// Client sends: VER(1) + NMETHODS(1) + METHODS(1..255)
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, fmt.Errorf("SOCKS5: failed to read method header: %w", err)
	}

	if hdr[0] != socks5Ver {
		return nil, fmt.Errorf("SOCKS5: bad version 0x%02x", hdr[0])
	}

	nmethods := hdr[1]
	if nmethods == 0 {
		logDebug("SOCKS5: no methods offered")
		conn.Write([]byte{socks5Ver, socks5AuthNoAccept})
		return nil, fmt.Errorf("SOCKS5: no methods offered")
	}

	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return nil, fmt.Errorf("SOCKS5: failed to read methods: %w", err)
	}

	// Scan for no-auth (0x00)
	foundNoAuth := slices.Contains(methods, socks5AuthNone)

	if !foundNoAuth {
		logDebug("SOCKS5: no acceptable auth method")
		conn.Write([]byte{socks5Ver, socks5AuthNoAccept})
		return nil, fmt.Errorf("SOCKS5: no acceptable auth method")
	}

	// Reply: select no-auth
	if _, err := conn.Write([]byte{socks5Ver, socks5AuthNone}); err != nil {
		return nil, fmt.Errorf("SOCKS5: failed to send method reply: %w", err)
	}

	// Phase 2: CONNECT request
	// Client sends: VER(1) + CMD(1) + RSV(1) + ATYP(1) + ADDR(var) + PORT(2)
	var reqHdr [4]byte
	if _, err := io.ReadFull(br, reqHdr[:]); err != nil {
		return nil, fmt.Errorf("SOCKS5: failed to read request header: %w", err)
	}

	if reqHdr[0] != socks5Ver {
		return nil, fmt.Errorf("SOCKS5: bad version in request 0x%02x", reqHdr[0])
	}

	if reqHdr[1] != socks5CmdConnect {
		logDebug("SOCKS5: unsupported command 0x%02x", reqHdr[1])
		socks5SendReply(conn, socks5RepCmdUnsupported)
		return nil, fmt.Errorf("SOCKS5: unsupported command 0x%02x", reqHdr[1])
	}

	atyp := reqHdr[3]
	var host string
	var port uint16

	switch atyp {
	case addrTypeIPv4:
		var addrPort [6]byte // 4 + 2
		if _, err := io.ReadFull(br, addrPort[:]); err != nil {
			return nil, fmt.Errorf("SOCKS5: failed to read IPv4 address: %w", err)
		}
		host = net.IP(addrPort[:4]).String()
		port = binary.BigEndian.Uint16(addrPort[4:])

	case addrTypeIPv6:
		var addrPort [18]byte // 16 + 2
		if _, err := io.ReadFull(br, addrPort[:]); err != nil {
			return nil, fmt.Errorf("SOCKS5: failed to read IPv6 address: %w", err)
		}
		host = net.IP(addrPort[:16]).String()
		port = binary.BigEndian.Uint16(addrPort[16:])

	case addrTypeDomain:
		var dlen [1]byte
		if _, err := io.ReadFull(br, dlen[:]); err != nil {
			return nil, fmt.Errorf("SOCKS5: failed to read domain length: %w", err)
		}
		if dlen[0] == 0 {
			return nil, fmt.Errorf("SOCKS5: zero-length domain name")
		}
		domain := make([]byte, dlen[0])
		if _, err := io.ReadFull(br, domain); err != nil {
			return nil, fmt.Errorf("SOCKS5: failed to read domain: %w", err)
		}
		host = string(domain)

		var portBuf [2]byte
		if _, err := io.ReadFull(br, portBuf[:]); err != nil {
			return nil, fmt.Errorf("SOCKS5: failed to read port: %w", err)
		}
		port = binary.BigEndian.Uint16(portBuf[:])

	default:
		logDebug("SOCKS5: unsupported address type 0x%02x", atyp)
		socks5SendReply(conn, socks5RepGeneral)
		return nil, fmt.Errorf("SOCKS5: unsupported address type 0x%02x", atyp)
	}

	logDebug("SOCKS5 parsed: %s:%d (atyp=0x%02x)", host, port, atyp)

	return &socks5Request{host: host, port: port}, nil
}

// socks5SendReply sends a SOCKS5 reply with the given status code.
// Uses a minimal reply with zeroed bind address (IPv4 0.0.0.0:0).
func socks5SendReply(conn net.Conn, rep byte) error {
	msg := [10]byte{socks5Ver, rep, 0x00, addrTypeIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(msg[:])
	return err
}
