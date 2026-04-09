package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Server is a SOCKS5 proxy server supporting CONNECT with optional auth.
type Server struct {
	listenAddr  string
	credentials map[string]string // username → password (empty map = no auth)
}

// NewServer creates a SOCKS5 server with a single credential pair.
// For multiple users, use NewServerMulti.
func NewServer(addr string, user, pass string) *Server {
	creds := make(map[string]string)
	if user != "" {
		creds[user] = pass
	}
	return &Server{listenAddr: addr, credentials: creds}
}

// NewServerMulti creates a SOCKS5 server with multiple credential pairs.
func NewServerMulti(addr string, creds map[string]string) *Server {
	if creds == nil {
		creds = make(map[string]string)
	}
	return &Server{listenAddr: addr, credentials: creds}
}

// ListenAndServe starts the SOCKS5 server (blocking).
func (s *Server) ListenAndServe() error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}

	ln, err := lc.Listen(context.Background(), "tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	log.Printf("SOCKS5 proxy listening on %s", s.listenAddr)

	// Graceful shutdown on SIGTERM/SIGINT
	done := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		log.Println("shutting down SOCKS5 proxy")
		close(done)
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return nil
			default:
			}
			log.Printf("accept: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Greeting: client sends version + auth methods
	buf := make([]byte, 258)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return // not SOCKS5
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}

	if len(s.credentials) > 0 {
		// Require username/password auth (method 0x02)
		conn.Write([]byte{0x05, 0x02})
		if !s.authenticate(conn) {
			return
		}
	} else {
		// No auth (method 0x00)
		conn.Write([]byte{0x05, 0x00})
	}

	// Request: version(1) + cmd(1) + rsv(1) + atyp(1)
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[2] != 0x00 {
		return
	}
	cmd := buf[1]
	atyp := buf[3]

	if cmd != 0x01 {
		// Only CONNECT supported
		s.sendReply(conn, 0x07, nil) // command not supported
		return
	}

	// Parse destination address
	var dstAddr string
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		dstAddr = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return
		}
		dstAddr = string(buf[:domainLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		dstAddr = net.IP(buf[:16]).String()
	default:
		s.sendReply(conn, 0x08, nil) // address type not supported
		return
	}

	// Port (2 bytes, big-endian)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])
	target := net.JoinHostPort(dstAddr, fmt.Sprintf("%d", port))

	// Connect to target
	remote, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		s.sendReply(conn, 0x05, nil) // connection refused
		return
	}
	defer remote.Close()

	// Success reply
	s.sendReply(conn, 0x00, remote.LocalAddr().(*net.TCPAddr))

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remote, conn)
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, remote)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()
}

func (s *Server) authenticate(conn net.Conn) bool {
	// RFC 1929: version(1) + ulen(1) + username(ulen) + plen(1) + password(plen)
	buf := make([]byte, 513)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return false
	}
	if buf[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01}) // failure
		return false
	}
	ulen := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:ulen]); err != nil {
		return false
	}
	user := string(buf[:ulen])

	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return false
	}
	plen := int(buf[0])
	if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
		return false
	}
	pass := string(buf[:plen])

	if expected, ok := s.credentials[user]; ok && expected == pass {
		conn.Write([]byte{0x01, 0x00}) // success
		return true
	}
	conn.Write([]byte{0x01, 0x01}) // failure
	return false
}

func (s *Server) sendReply(conn net.Conn, status byte, addr *net.TCPAddr) {
	reply := []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if addr != nil {
		ip := addr.IP.To4()
		if ip != nil {
			copy(reply[4:8], ip)
		}
		reply[8] = byte(addr.Port >> 8)
		reply[9] = byte(addr.Port)
	}
	conn.Write(reply)
}

// Serve starts the built-in SOCKS5 proxy.
func Serve(addr string, port int, user, pass string) error {
	listenAddr := fmt.Sprintf("%s:%d", addr, port)
	srv := NewServer(listenAddr, user, pass)
	return srv.ListenAndServe()
}

// ServeMulti starts the built-in SOCKS5 proxy with multiple credentials.
func ServeMulti(addr string, port int, creds map[string]string) error {
	listenAddr := fmt.Sprintf("%s:%d", addr, port)
	srv := NewServerMulti(listenAddr, creds)
	return srv.ListenAndServe()
}
