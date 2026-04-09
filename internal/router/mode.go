package router

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/dnsrouter"
	"github.com/anonvector/slipgate/internal/service"
)

// SwitchMode is kept for backward compatibility but all tunnels now use the
// DNS router. Restarting services ensures they bind to internal ports.
func SwitchMode(cfg *config.Config, newMode string) error {
	// Restart all managed DNS tunnel services to pick up config changes
	for _, t := range cfg.Tunnels {
		if t.HasManagedService() && t.Enabled {
			svcName := service.TunnelServiceName(t.Tag)
			if err := service.Restart(svcName); err != nil {
				return fmt.Errorf("restart tunnel %s: %w", t.Tag, err)
			}
		}
	}

	// Ensure DNS router is running
	return ensureRouterRunning()
}

// SwitchActive changes the active tunnel (stops others, starts the selected one).
func SwitchActive(cfg *config.Config, tag string) error {
	tunnel := cfg.GetTunnel(tag)
	if tunnel == nil {
		return fmt.Errorf("tunnel %q not found", tag)
	}

	if cfg.Route.Active != "" && cfg.Route.Active != tag {
		old := cfg.GetTunnel(cfg.Route.Active)
		if old != nil && old.HasManagedService() {
			oldName := service.TunnelServiceName(cfg.Route.Active)
			_ = service.Stop(oldName)
		}
	}

	if tunnel.HasManagedService() {
		newName := service.TunnelServiceName(tag)
		if err := service.Start(newName); err != nil {
			return err
		}
	}

	return dnsrouter.RestartRouterService()
}

func ensureRouterRunning() error {
	status, err := service.Status("slipgate-dnsrouter")
	if err != nil || status != "active" {
		if err := dnsrouter.CreateRouterService(); err != nil {
			return err
		}
		return dnsrouter.StartRouterService()
	}
	return nil
}
