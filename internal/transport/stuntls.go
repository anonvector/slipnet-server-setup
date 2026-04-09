package transport

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
)

func createStunTLSService(tunnel *config.TunnelConfig, cfg *config.Config) error {
	if tunnel.StunTLS == nil {
		return fmt.Errorf("stuntls config is nil")
	}

	// slipgate binary itself serves as the TLS proxy — no external binary needed
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}

	port := tunnel.StunTLS.Port
	if port == 0 {
		port = 443
	}

	sshAddr := "127.0.0.1:22"

	unit := &service.Unit{
		Name:        service.TunnelServiceName(tunnel.Tag),
		Description: fmt.Sprintf("SlipGate StunTLS: %s", tunnel.Tag),
		ExecStart: fmt.Sprintf("%s stuntls serve --addr 0.0.0.0 --port %d --ssh %s --cert %s --key %s",
			execPath, port, sshAddr, tunnel.StunTLS.Cert, tunnel.StunTLS.Key),
		User:    "root",
		Group:   config.SystemGroup,
		After:   "network.target",
		Restart: "always",
	}

	if err := service.Create(unit); err != nil {
		return err
	}

	if _, err := service.Status(unit.Name); err == nil {
		return service.Restart(unit.Name)
	}
	return service.Start(unit.Name)
}

// TunnelDir returns the data directory for a StunTLS tunnel (for cert/key storage).
func stuntlsTunnelDir(tag string) string {
	return filepath.Join(config.DefaultConfigDir, "tunnels", tag)
}
