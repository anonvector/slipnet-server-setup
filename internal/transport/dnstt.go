package transport

import (
	"fmt"
	"path/filepath"

	"github.com/anonvector/slipgate/internal/config"
)

// buildDNSTTExecStart builds the ExecStart for dnstt-server.
// dnstt-server -udp ADDR -privkey-file KEY [-mtu MTU] DOMAIN UPSTREAMADDR
func buildDNSTTExecStart(tunnel *config.TunnelConfig, cfg *config.Config) (string, error) {
	if tunnel.DNSTT == nil {
		return "", fmt.Errorf("dnstt config is nil")
	}

	backend := cfg.GetBackend(tunnel.Backend)
	if backend == nil {
		return "", fmt.Errorf("backend %q not found", tunnel.Backend)
	}

	binPath := filepath.Join(config.DefaultBinDir, "dnstt-server")
	listenAddr := fmt.Sprintf("0.0.0.0:%d", tunnel.Port)

	mtu := tunnel.DNSTT.MTU
	if mtu == 0 {
		mtu = config.DefaultMTU
	}

	return fmt.Sprintf("%s -udp %s -privkey-file %s -mtu %d %s %s",
		binPath,
		listenAddr,
		tunnel.DNSTT.PrivateKey,
		mtu,
		tunnel.Domain,
		backend.Address,
	), nil
}
