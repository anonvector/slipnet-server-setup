package router

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
)

// SwitchMode transitions between single and multi mode.
func SwitchMode(cfg *config.Config, newMode string) error {
	oldMode := cfg.Route.Mode

	switch {
	case oldMode == "single" && newMode == "multi":
		return switchToMulti(cfg)
	case oldMode == "multi" && newMode == "single":
		return switchToSingle(cfg)
	default:
		return fmt.Errorf("already in %s mode", newMode)
	}
}

func switchToMulti(cfg *config.Config) error {
	// Start all DNS tunnel services on their internal ports
	for _, t := range cfg.Tunnels {
		if t.IsDNSTunnel() && t.Enabled {
			svcName := service.TunnelServiceName(t.Tag)
			if err := service.Restart(svcName); err != nil {
				return fmt.Errorf("start tunnel %s: %w", t.Tag, err)
			}
		}
	}

	// Ensure the DNS router is running (forwards :53 → internal ports)
	return ensureRouterRunning()
}

func switchToSingle(cfg *config.Config) error {
	// Stop all DNS tunnel services except the active one
	for _, t := range cfg.Tunnels {
		if t.IsDNSTunnel() && t.Enabled && t.Tag != cfg.Route.Active {
			svcName := service.TunnelServiceName(t.Tag)
			_ = service.Stop(svcName)
		}
	}

	// Restart the active tunnel on its internal port
	if cfg.Route.Active != "" {
		svcName := service.TunnelServiceName(cfg.Route.Active)
		if err := service.Restart(svcName); err != nil {
			return fmt.Errorf("restart active tunnel: %w", err)
		}
	}

	// DNS router must stay running to forward :53 → internal ports
	return ensureRouterRunning()
}
