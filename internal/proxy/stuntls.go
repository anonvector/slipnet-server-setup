package proxy

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// StunTLSServer accepts TLS connections and forwards traffic to SSH.
// It auto-detects the client protocol by peeking at the first bytes:
//   - "GET "    → WebSocket: HTTP upgrade, then relay WS binary frames ↔ TCP
//   - "CONNECT" → HTTP CONNECT proxy: tunnel through to SSH backend
//   - "SSH-"    → Raw SSH over TLS (stunnel-compatible)
//   - other     → Payload mode: skip non-SSH prefix bytes, then relay to SSH
type StunTLSServer struct {
	listenAddr string
	sshAddr    string
	tlsCert    string
	tlsKey     string
}

// NewStunTLSServer creates a TLS+WebSocket SSH proxy.
func NewStunTLSServer(listenAddr, sshAddr, certFile, keyFile string) *StunTLSServer {
	return &StunTLSServer{
		listenAddr: listenAddr,
		sshAddr:    sshAddr,
		tlsCert:    certFile,
		tlsKey:     keyFile,
	}
}

// ListenAndServe starts the TLS listener (blocking).
func (s *StunTLSServer) ListenAndServe() error {
	cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
	if err != nil {
		return fmt.Errorf("load TLS cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", s.listenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	log.Printf("StunTLS proxy listening on %s → %s", s.listenAddr, s.sshAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *StunTLSServer) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Peek at first bytes to detect protocol
	br := bufio.NewReaderSize(conn, 4096)
	first, err := br.Peek(4)
	if err != nil {
		return
	}
	prefix := string(first)

	conn.SetDeadline(time.Time{}) // clear deadline

	switch {
	case prefix == "GET ":
		// WebSocket upgrade
		s.handleWebSocket(br, conn)
	case prefix == "CONN":
		// HTTP CONNECT proxy
		s.handleHTTPConnect(br, conn)
	case prefix == "SSH-":
		// Raw SSH banner — relay directly (stunnel mode)
		s.handleRaw(br, conn)
	default:
		// Unknown prefix — likely a payload (raw bytes before SSH banner).
		// Scan forward to find the SSH-2.0 banner, discard everything before it,
		// then relay the SSH stream to the backend.
		s.handlePayload(br, conn)
	}
}

// handleRaw relays raw TCP (stunnel mode) — SSH directly over TLS.
func (s *StunTLSServer) handleRaw(br *bufio.Reader, conn net.Conn) {
	remote, err := net.DialTimeout("tcp", s.sshAddr, 10*time.Second)
	if err != nil {
		log.Printf("raw: dial SSH: %v", err)
		return
	}
	defer remote.Close()

	relay(newPeekedConn(br, conn), remote)
}

// handleHTTPConnect handles HTTP CONNECT proxy requests.
// The client sends "CONNECT host:port HTTP/1.1\r\n...\r\n\r\n",
// we reply with 200, then relay the tunneled connection to SSH.
func (s *StunTLSServer) handleHTTPConnect(br *bufio.Reader, conn net.Conn) {
	// Read the full HTTP request (reuse the existing parser)
	req, err := readHTTPRequest(br)
	if err != nil {
		log.Printf("connect: read request: %v", err)
		return
	}
	if req.method != "CONNECT" {
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}

	log.Printf("connect: CONNECT %s", req.path)

	// Connect to SSH backend
	remote, err := net.DialTimeout("tcp", s.sshAddr, 10*time.Second)
	if err != nil {
		log.Printf("connect: dial SSH: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	// Send 200 to indicate tunnel is established
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Relay bidirectionally — from here on, the client runs SSH (or TLS+SSH) inside the tunnel
	relay(newPeekedConn(br, conn), remote)
}

// handlePayload handles connections that start with a non-SSH prefix (payload/DPI bypass).
// It scans the incoming stream for the SSH version banner ("SSH-"), discards everything
// before it, then relays the SSH session to the backend.
func (s *StunTLSServer) handlePayload(br *bufio.Reader, conn net.Conn) {
	// Scan byte-by-byte for "SSH-" (max 8KB to prevent abuse)
	const maxScan = 8192
	scanned := 0
	matchIdx := 0
	target := []byte("SSH-")

	for scanned < maxScan {
		b, err := br.ReadByte()
		if err != nil {
			return
		}
		scanned++

		if b == target[matchIdx] {
			matchIdx++
			if matchIdx == len(target) {
				// Found "SSH-" — unread the matched bytes so the SSH banner is intact
				if err := br.UnreadByte(); err != nil {
					return
				}
				// UnreadByte only unreads 1 byte; we need to prepend "SSH" to the stream.
				// Create a new reader that starts with "SSH" + rest of br.
				prefix := io.MultiReader(strings.NewReader("SSH"), br)
				prefixConn := &readerConn{Reader: prefix, Conn: conn}

				remote, err := net.DialTimeout("tcp", s.sshAddr, 10*time.Second)
				if err != nil {
					log.Printf("payload: dial SSH: %v", err)
					return
				}
				defer remote.Close()

				log.Printf("payload: found SSH banner after %d bytes of payload", scanned-len(target))
				relay(prefixConn, remote)
				return
			}
		} else {
			// Reset match — but check if current byte starts a new match
			if matchIdx > 0 {
				matchIdx = 0
				if b == target[0] {
					matchIdx = 1
				}
			}
		}
	}
	log.Printf("payload: no SSH banner found within %d bytes, dropping", maxScan)
}

// readerConn wraps a custom Reader with an existing net.Conn for writes/close.
type readerConn struct {
	io.Reader
	net.Conn
}

func (c *readerConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }

// handleWebSocket performs WebSocket upgrade, then relays WS frames ↔ SSH TCP.
func (s *StunTLSServer) handleWebSocket(br *bufio.Reader, conn net.Conn) {
	// Read the HTTP request
	req, err := readHTTPRequest(br)
	if err != nil {
		log.Printf("ws: read request: %v", err)
		return
	}

	// Verify it's a WebSocket upgrade
	if !strings.EqualFold(req.headers["upgrade"], "websocket") {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// Send 101 Switching Protocols
	wsKey := req.headers["sec-websocket-key"]
	acceptKey := computeAcceptKey(wsKey)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}

	// Connect to SSH backend
	remote, err := net.DialTimeout("tcp", s.sshAddr, 10*time.Second)
	if err != nil {
		log.Printf("ws: dial SSH: %v", err)
		// Send WS close frame
		writeWSClose(conn)
		return
	}
	defer remote.Close()

	// Relay: WS frames from client → raw TCP to SSH, and vice versa
	var wg sync.WaitGroup
	wg.Add(2)

	// Client → SSH: read WS frames, write raw TCP
	go func() {
		defer wg.Done()
		wsToTCP(br, remote)
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// SSH → Client: read raw TCP, write WS frames
	go func() {
		defer wg.Done()
		tcpToWS(remote, conn)
	}()

	wg.Wait()
}

// wsToTCP reads WebSocket frames and writes raw payloads to dst.
func wsToTCP(src *bufio.Reader, dst net.Conn) {
	for {
		opcode, payload, err := readWSFrame(src)
		if err != nil {
			return
		}
		switch opcode {
		case 0x1, 0x2, 0x0: // text, binary, continuation
			if _, err := dst.Write(payload); err != nil {
				return
			}
		case 0x8: // close
			return
		case 0x9: // ping → pong
			writeWSFrame(dst, 0xA, payload)
		case 0xA: // pong — ignore
		}
	}
}

// tcpToWS reads raw TCP and writes WebSocket binary frames to dst.
func tcpToWS(src net.Conn, dst net.Conn) {
	buf := make([]byte, 32768)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if werr := writeWSFrame(dst, 0x2, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			writeWSClose(dst)
			return
		}
	}
}

// readWSFrame reads a single WebSocket frame. Handles client masking.
func readWSFrame(br *bufio.Reader) (opcode byte, payload []byte, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(br, hdr); err != nil {
		return
	}

	opcode = hdr[0] & 0x0F
	masked := (hdr[1] & 0x80) != 0
	length := uint64(hdr[1] & 0x7F)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(br, ext); err != nil {
			return
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(br, ext); err != nil {
			return
		}
		length = binary.BigEndian.Uint64(ext)
	}

	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(br, mask[:]); err != nil {
			return
		}
	}

	payload = make([]byte, length)
	if _, err = io.ReadFull(br, payload); err != nil {
		return
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return
}

// writeWSFrame writes an unmasked WebSocket frame (server → client).
func writeWSFrame(w net.Conn, opcode byte, payload []byte) error {
	length := len(payload)
	var hdr []byte

	if length <= 125 {
		hdr = []byte{0x80 | opcode, byte(length)}
	} else if length <= 65535 {
		hdr = make([]byte, 4)
		hdr[0] = 0x80 | opcode
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(length))
	} else {
		hdr = make([]byte, 10)
		hdr[0] = 0x80 | opcode
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(length))
	}

	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if length > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func writeWSClose(w net.Conn) {
	writeWSFrame(w, 0x8, []byte{0x03, 0xE8}) // 1000 normal closure
}

// relay copies bidirectionally between two connections.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// --- HTTP request parsing (minimal, for WebSocket upgrade only) ---

type httpRequest struct {
	method  string
	path    string
	headers map[string]string
}

func readHTTPRequest(br *bufio.Reader) (*httpRequest, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("bad request line")
	}

	req := &httpRequest{
		method:  parts[0],
		path:    parts[1],
		headers: make(map[string]string),
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		req.headers[key] = val
	}
	return req, nil
}

// computeAcceptKey generates the Sec-WebSocket-Accept value per RFC 6455.
func computeAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// peekedConn wraps a buffered reader + underlying conn so the peeked bytes are read first.
type peekedConn struct {
	br   *bufio.Reader
	conn net.Conn
}

func newPeekedConn(br *bufio.Reader, conn net.Conn) *peekedConn {
	return &peekedConn{br: br, conn: conn}
}

func (c *peekedConn) Read(b []byte) (int, error)         { return c.br.Read(b) }
func (c *peekedConn) Write(b []byte) (int, error)        { return c.conn.Write(b) }
func (c *peekedConn) Close() error                       { return c.conn.Close() }
func (c *peekedConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *peekedConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *peekedConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *peekedConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *peekedConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// ServeStunTLS starts the built-in TLS+WebSocket SSH proxy.
func ServeStunTLS(addr string, port int, sshAddr, certFile, keyFile string) error {
	listenAddr := fmt.Sprintf("%s:%d", addr, port)
	srv := NewStunTLSServer(listenAddr, sshAddr, certFile, keyFile)
	return srv.ListenAndServe()
}
