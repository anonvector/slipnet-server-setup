package config

import "math/rand"

// BasePort is the starting port for DNS tunnel forwarding.
const BasePort = 5310

// decoySites is a list of popular, high-traffic HTTPS sites used as decoys.
var decoySites = []string{
	"https://www.wikipedia.org",
	"https://www.apache.org",
	"https://www.kernel.org",
	"https://www.mozilla.org",
	"https://www.python.org",
	"https://www.rust-lang.org",
	"https://www.gnu.org",
	"https://www.ietf.org",
	"https://www.w3.org",
	"https://www.unicode.org",
	"https://www.archive.org",
	"https://www.debian.org",
	"https://www.ubuntu.com",
	"https://www.freebsd.org",
	"https://www.openbsd.org",
}

// RandomDecoyURL returns a random decoy site URL.
func RandomDecoyURL() string {
	return decoySites[rand.Intn(len(decoySites))]
}

// NextAvailablePort returns the next unused port starting from BasePort.
func (c *Config) NextAvailablePort() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	used := make(map[int]bool)
	for _, t := range c.Tunnels {
		if t.Port > 0 {
			used[t.Port] = true
		}
	}
	for port := BasePort; ; port++ {
		if !used[port] {
			return port
		}
	}
}

// DefaultBackends returns the standard backend configs.
func DefaultBackends() []BackendConfig {
	return []BackendConfig{
		{Tag: "socks", Type: BackendSOCKS, Address: "127.0.0.1:1080", SOCKS: &SOCKSConfig{}},
		{Tag: "ssh", Type: BackendSSH, Address: "127.0.0.1:22"},
	}
}

// DefaultMTU for DNS tunnels.
const DefaultMTU = 1232

// TransportBinaries maps transport types to their required binaries.
var TransportBinaries = map[string]string{
	TransportDNSTT:      "dnstt-server",
	TransportSlipstream: "slipstream-server",
	TransportVayDNS:     "vaydns-server",
	TransportNaive:      "caddy-naive",
}
