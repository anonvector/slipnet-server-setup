package config

// Transport types.
const (
	TransportDNSTT      = "dnstt"
	TransportSlipstream = "slipstream"
	TransportNaive      = "naive"
	TransportSSH        = "direct-ssh"
	TransportSOCKS      = "direct-socks5"
)

// TunnelConfig defines a single tunnel.
type TunnelConfig struct {
	Tag       string `json:"tag"`
	Transport string `json:"transport"`
	Backend   string `json:"backend"`
	Domain    string `json:"domain"`
	Port      int    `json:"port,omitempty"` // DNS tunnels: internal forwarding port (5310+)
	Enabled   bool   `json:"enabled"`

	// Transport-specific configs (only one set per tunnel)
	DNSTT      *DNSTTConfig      `json:"dnstt,omitempty"`
	Slipstream *SlipstreamConfig `json:"slipstream,omitempty"`
	Naive      *NaiveConfig      `json:"naive,omitempty"`
}

// DNSTTConfig holds config for DNSTT transport (serves both DNSTT and NoizDNS clients).
type DNSTTConfig struct {
	MTU        int    `json:"mtu"`
	PrivateKey string `json:"private_key"` // path to key file
	PublicKey  string `json:"public_key"`  // hex-encoded public key
}

// SlipstreamConfig holds config for slipstream transport.
type SlipstreamConfig struct {
	Cert string `json:"cert"` // path to cert file
	Key  string `json:"key"`  // path to key file
}

// NaiveConfig holds config for naiveproxy transport.
type NaiveConfig struct {
	Email    string `json:"email"`
	DecoyURL string `json:"decoy_url"`
	Port     int    `json:"port"` // typically 443
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
}

// IsDNSTunnel returns true if the transport uses DNS port 53.
func (t *TunnelConfig) IsDNSTunnel() bool {
	switch t.Transport {
	case TransportDNSTT, TransportSlipstream:
		return true
	}
	return false
}

// IsDirectTransport returns true for transports that expose a service directly (no tunnel).
func (t *TunnelConfig) IsDirectTransport() bool {
	switch t.Transport {
	case TransportSSH, TransportSOCKS:
		return true
	}
	return false
}
