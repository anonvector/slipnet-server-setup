package transport

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
)

// CreateService creates and starts a systemd service for a tunnel.
func CreateService(tunnel *config.TunnelConfig, cfg *config.Config) error {
	switch tunnel.Transport {
	case config.TransportDNSTT:
		return createDNSService(tunnel, cfg)
	case config.TransportSlipstream:
		return createDNSService(tunnel, cfg)
	case config.TransportNaive:
		return createNaiveService(tunnel, cfg)
	default:
		return fmt.Errorf("unknown transport: %s", tunnel.Transport)
	}
}

func createDNSService(tunnel *config.TunnelConfig, cfg *config.Config) error {
	var execStart string
	var err error

	switch tunnel.Transport {
	case config.TransportDNSTT:
		execStart, err = buildDNSTTExecStart(tunnel, cfg)
	case config.TransportSlipstream:
		execStart, err = buildSlipstreamExecStart(tunnel, cfg)
	}
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

// RemoveService stops and removes a tunnel's systemd service.
func RemoveService(tag string) error {
	name := service.TunnelServiceName(tag)
	_ = service.Stop(name)
	return service.Remove(name)
}
