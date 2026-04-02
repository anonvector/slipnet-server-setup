package transport

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
)

func createVayDNSService(tunnel *config.TunnelConfig, cfg *config.Config) error {
	execStart, err := buildVayDNSExecStart(tunnel, cfg)
	if err != nil {
		return err
	}

	unit := &service.Unit{
		Name:        service.TunnelServiceName(tunnel.Tag),
		Description: fmt.Sprintf("SlipGate tunnel: %s (%s/%s)", tunnel.Tag, tunnel.Transport, tunnel.Backend),
		ExecStart:   execStart,
		User:        "root",
		Group:       config.SystemGroup,
		After:       "network.target",
		Restart:     "always",
	}

	if err := service.Create(unit); err != nil {
		return err
	}
	return service.Start(unit.Name)
}

// buildVayDNSExecStart builds the ExecStart command for vaydns-server.
func buildVayDNSExecStart(tunnel *config.TunnelConfig, cfg *config.Config) (string, error) {
	if tunnel.VayDNS == nil {
		return "", fmt.Errorf("vaydns config is nil")
	}

	backend := cfg.GetBackend(tunnel.Backend)
	if backend == nil {
		return "", fmt.Errorf("backend %q not found", tunnel.Backend)
	}

	binPath := filepath.Join(config.DefaultBinDir, "vaydns-server")

	mtu := tunnel.VayDNS.MTU
	if mtu == 0 {
		mtu = config.DefaultMTU
	}

	args := []string{
		"-udp", fmt.Sprintf("0.0.0.0:%d", tunnel.Port),
		"-privkey-file", tunnel.VayDNS.PrivateKey,
		"-mtu", strconv.Itoa(mtu),
		"-domain", tunnel.Domain,
		"-upstream", backend.Address,
		"-idle-timeout", tunnel.VayDNS.ResolvedIdleTimeout(),
		"-keepalive", tunnel.VayDNS.ResolvedKeepAlive(),
	}

	if tunnel.VayDNS.Fallback != "" {
		args = append(args, "-fallback", tunnel.VayDNS.Fallback)
	}
	if tunnel.VayDNS.DnsttCompat {
		args = append(args, "-dnstt-compat")
	}
	if n := tunnel.VayDNS.ResolvedClientIDSize(); n > 0 {
		args = append(args, "-clientid-size", strconv.Itoa(n))
	}
	if tunnel.VayDNS.QueueSize > 0 && tunnel.VayDNS.QueueSize != 512 {
		args = append(args, "-queue-size", strconv.Itoa(tunnel.VayDNS.QueueSize))
	}
	if tunnel.VayDNS.KCPWindowSize > 0 {
		args = append(args, "-kcp-window-size", strconv.Itoa(tunnel.VayDNS.KCPWindowSize))
	}
	if tunnel.VayDNS.QueueOverflow != "" && tunnel.VayDNS.QueueOverflow != "drop" {
		args = append(args, "-queue-overflow", tunnel.VayDNS.QueueOverflow)
	}
	if tunnel.VayDNS.RecordType != "" && tunnel.VayDNS.RecordType != "txt" {
		args = append(args, "-record-type", tunnel.VayDNS.RecordType)
	}

	return fmt.Sprintf("%s %s", binPath, strings.Join(args, " ")), nil
}
