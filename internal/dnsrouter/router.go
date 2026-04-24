package dnsrouter

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anonvector/slipgate/internal/config"
)

// Router is a pure Go DNS forwarder that routes queries by domain.
type Router struct {
	listenAddr   string
	routes       map[string]string // domain → backend address (host:port)
	verifyRoutes []verifyRoute     // HMAC verification routes
	defaultDst   string
	mu           sync.RWMutex
	conn         *net.UDPConn

	// Persistent backend connections and pending query tracking
	backends    map[string]*backendConn
	backendsMu  sync.Mutex
}

// backendConn is a persistent UDP connection to a backend (dnstt-server).
type backendConn struct {
	conn     *net.UDPConn
	pending  sync.Map      // serverTxID (uint16) → *pendingQuery
	nextTxID atomic.Uint32 // counter for server-side TXID allocation
}

// pendingQuery tracks a forwarded query so the response can be routed back.
// originalTxID is the client's TXID, which we restore before writing the
// response back. Multiplexing clients over a single backend UDP socket
// requires server-generated TXIDs; using the client's TXID directly would
// cause cross-client collisions (two clients easily pick the same 16-bit ID)
// and mis-deliver responses.
type pendingQuery struct {
	clientAddr   *net.UDPAddr
	originalTxID uint16
	timestamp    time.Time
}

// New creates a new DNS router.
func New(listenAddr string) *Router {
	return &Router{
		listenAddr: listenAddr,
		routes:     make(map[string]string),
		backends:   make(map[string]*backendConn),
	}
}

// AddRoute maps a domain to a backend address.
func (r *Router) AddRoute(domain, backend string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Normalize: ensure trailing dot
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	r.routes[strings.ToLower(domain)] = backend
}

// AddVerifyRoute registers a domain's public key and MTU for HMAC verification.
func (r *Router) AddVerifyRoute(domain string, pubkey []byte, mtu int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	r.verifyRoutes = append(r.verifyRoutes, verifyRoute{
		domainLabels: strings.Split(domain, "."),
		pubkey:       pubkey,
		mtu:          mtu,
	})
}

// SetDefault sets the default backend for unmatched queries.
func (r *Router) SetDefault(backend string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultDst = backend
}

// ListenAndServe starts the DNS router.
func (r *Router) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", r.listenAddr)
	if err != nil {
		return fmt.Errorf("resolve listen addr: %w", err)
	}

	r.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	defer r.conn.Close()

	log.Printf("DNS router listening on %s", r.listenAddr)

	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}

		// Copy packet for goroutine
		packet := make([]byte, n)
		copy(packet, buf[:n])

		go r.handleQuery(packet, clientAddr)
	}
}

func (r *Router) handleQuery(packet []byte, clientAddr *net.UDPAddr) {
	// Check for HMAC verification query first
	if r.handleVerify(packet, clientAddr) {
		return
	}

	// Extract domain from DNS query
	domain := extractDomain(packet)
	if domain == "" {
		return
	}

	// Find matching backend
	r.mu.RLock()
	backend := r.findBackend(domain)
	r.mu.RUnlock()

	if backend == "" {
		return
	}

	// Forward via persistent backend connection
	bc, err := r.getBackend(backend)
	if err != nil {
		log.Printf("backend %s: %v", backend, err)
		return
	}

	if len(packet) < 2 {
		return
	}
	originalTxID := binary.BigEndian.Uint16(packet[:2])

	pq := &pendingQuery{
		clientAddr:   clientAddr,
		originalTxID: originalTxID,
		timestamp:    time.Now(),
	}

	// Allocate a server-side TXID that isn't currently in use. LoadOrStore
	// reserves the slot atomically; if it's already taken (rare — pending
	// entries expire after 10s and the allocation space is 65536), advance.
	var serverTxID uint16
	var stored bool
	for i := 0; i < 65536; i++ {
		candidate := uint16(bc.nextTxID.Add(1))
		if _, loaded := bc.pending.LoadOrStore(candidate, pq); !loaded {
			serverTxID = candidate
			stored = true
			break
		}
	}
	if !stored {
		log.Printf("dnsrouter: pending TXID space exhausted for backend %s, dropping query from %s", backend, clientAddr)
		return
	}

	// Rewrite the query's TXID to the server-side value. `packet` was copied
	// in the Listen loop before being handed off, so it's safe to mutate.
	binary.BigEndian.PutUint16(packet[:2], serverTxID)

	if _, err := bc.conn.Write(packet); err != nil {
		bc.pending.Delete(serverTxID)
		log.Printf("write to %s: %v", backend, err)
	}
}

// getBackend returns a persistent connection to the backend, creating one if needed.
func (r *Router) getBackend(addr string) (*backendConn, error) {
	r.backendsMu.Lock()
	defer r.backendsMu.Unlock()

	if bc, ok := r.backends[addr]; ok {
		return bc, nil
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}

	bc := &backendConn{conn: conn}
	r.backends[addr] = bc

	// Start response reader goroutine
	go r.readBackendResponses(bc, addr)

	// Start stale query cleanup
	go r.cleanPending(bc)

	return bc, nil
}

// readBackendResponses reads responses from a backend and routes them to clients.
func (r *Router) readBackendResponses(bc *backendConn, addr string) {
	buf := make([]byte, 4096)
	for {
		n, err := bc.conn.Read(buf)
		if err != nil {
			log.Printf("read from %s: %v", addr, err)
			return
		}
		if n < 2 {
			continue
		}

		serverTxID := binary.BigEndian.Uint16(buf[:2])
		val, ok := bc.pending.LoadAndDelete(serverTxID)
		if !ok {
			continue // no matching query (stale or duplicate)
		}

		pq := val.(*pendingQuery)
		// Restore the client's original TXID before forwarding.
		binary.BigEndian.PutUint16(buf[:2], pq.originalTxID)
		r.conn.WriteToUDP(buf[:n], pq.clientAddr)
	}
}

// cleanPending removes stale pending queries every 30 seconds.
func (r *Router) cleanPending(bc *backendConn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		bc.pending.Range(func(key, value any) bool {
			pq := value.(*pendingQuery)
			if now.Sub(pq.timestamp) > 10*time.Second {
				bc.pending.Delete(key)
			}
			return true
		})
	}
}

func (r *Router) findBackend(domain string) string {
	domain = strings.ToLower(domain)
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// Try exact match first
	if dst, ok := r.routes[domain]; ok {
		return dst
	}

	// Try suffix match (for subdomains)
	for routeDomain, dst := range r.routes {
		if strings.HasSuffix(domain, "."+routeDomain) || domain == routeDomain {
			return dst
		}
	}

	return r.defaultDst
}

// Serve loads config and starts the DNS router.
func Serve(cfgInterface interface{}) error {
	cfg, ok := cfgInterface.(*config.Config)
	if !ok {
		return fmt.Errorf("invalid config type")
	}

	r := New(cfg.Listen.Address)

	for _, tunnel := range cfg.Tunnels {
		if !tunnel.Enabled || !tunnel.IsDNSTunnel() {
			continue
		}
		backend := fmt.Sprintf("127.0.0.1:%d", tunnel.Port)
		r.AddRoute(tunnel.Domain, backend)
		log.Printf("route: %s → %s", tunnel.Domain, backend)

		// Register HMAC verification
		switch tunnel.Transport {
		case config.TransportDNSTT:
			if tunnel.DNSTT != nil && tunnel.DNSTT.PublicKey != "" {
				pubkey, err := loadPubkey(tunnel.DNSTT.PublicKey)
				if err != nil {
					log.Printf("verify: skip %s: %v", tunnel.Tag, err)
					continue
				}
				mtu := tunnel.DNSTT.MTU
				if mtu == 0 {
					mtu = config.DefaultMTU
				}
				r.AddVerifyRoute(tunnel.Domain, pubkey, mtu)
				log.Printf("verify: %s (HMAC via pubkey, mtu=%d)", tunnel.Domain, mtu)
			}
		case config.TransportVayDNS:
			if tunnel.VayDNS != nil && tunnel.VayDNS.PublicKey != "" {
				pubkey, err := loadPubkey(tunnel.VayDNS.PublicKey)
				if err != nil {
					log.Printf("verify: skip %s: %v", tunnel.Tag, err)
					continue
				}
				mtu := tunnel.VayDNS.MTU
				if mtu == 0 {
					mtu = config.DefaultMTU
				}
				r.AddVerifyRoute(tunnel.Domain, pubkey, mtu)
				log.Printf("verify: %s (HMAC via pubkey, mtu=%d)", tunnel.Domain, mtu)
			}
		case config.TransportSlipstream:
			if tunnel.Slipstream != nil && tunnel.Slipstream.Cert != "" {
				hmacKey, err := certToHMACKey(tunnel.Slipstream.Cert)
				if err != nil {
					log.Printf("verify: skip %s: %v", tunnel.Tag, err)
					continue
				}
				r.AddVerifyRoute(tunnel.Domain, hmacKey, 0)
				log.Printf("verify: %s (HMAC via cert fingerprint)", tunnel.Domain)
			}
		}
	}

	if cfg.Route.Default != "" {
		defaultTunnel := cfg.GetTunnel(cfg.Route.Default)
		if defaultTunnel != nil && defaultTunnel.IsDNSTunnel() {
			r.SetDefault(fmt.Sprintf("127.0.0.1:%d", defaultTunnel.Port))
		}
	}

	return r.ListenAndServe()
}

// certToHMACKey derives a 32-byte HMAC key from a PEM certificate file.
func certToHMACKey(certPath string) ([]byte, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", certPath)
	}
	hash := sha256.Sum256(block.Bytes)
	return hash[:], nil
}

// loadPubkey loads a hex-encoded public key.
func loadPubkey(pubkeyOrPath string) ([]byte, error) {
	hexStr := pubkeyOrPath
	if _, err := os.Stat(pubkeyOrPath); err == nil {
		data, err := os.ReadFile(pubkeyOrPath)
		if err != nil {
			return nil, fmt.Errorf("read pubkey file: %w", err)
		}
		hexStr = strings.TrimSpace(string(data))
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode pubkey hex: %w", err)
	}
	return b, nil
}
