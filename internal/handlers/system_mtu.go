package handlers

import (
	"fmt"
	"strconv"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/transport"
)

func handleSystemMTU(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output

	var affected []*config.TunnelConfig
	for i := range cfg.Tunnels {
		t := &cfg.Tunnels[i]
		if t.Transport == config.TransportDNSTT || t.Transport == config.TransportVayDNS {
			affected = append(affected, t)
		}
	}

	if len(affected) == 0 {
		out.Info("No DNSTT/NoizDNS/VayDNS tunnels configured")
		return nil
	}

	current := 0
	for _, t := range affected {
		var v int
		switch t.Transport {
		case config.TransportDNSTT:
			if t.DNSTT != nil {
				v = t.DNSTT.MTU
			}
		case config.TransportVayDNS:
			if t.VayDNS != nil {
				v = t.VayDNS.MTU
			}
		}
		if v == 0 {
			v = config.DefaultMTU
		}
		if current == 0 {
			current = v
		}
		out.Print(fmt.Sprintf("  %s (%s): MTU=%d", t.Tag, t.Transport, v))
	}

	mtuStr := ctx.GetArg("mtu")
	if mtuStr == "" {
		var err error
		mtuStr, err = prompt.String("New MTU for all DNS tunnels", strconv.Itoa(current))
		if err != nil {
			return err
		}
	}

	newMTU, err := strconv.Atoi(mtuStr)
	if err != nil || newMTU <= 0 {
		return actions.NewError(actions.SystemMTU, fmt.Sprintf("invalid MTU %q", mtuStr), nil)
	}

	changed := 0
	for _, t := range affected {
		switch t.Transport {
		case config.TransportDNSTT:
			if t.DNSTT != nil && t.DNSTT.MTU != newMTU {
				t.DNSTT.MTU = newMTU
				changed++
			}
		case config.TransportVayDNS:
			if t.VayDNS != nil && t.VayDNS.MTU != newMTU {
				t.VayDNS.MTU = newMTU
				changed++
			}
		}
	}

	if changed == 0 {
		out.Info(fmt.Sprintf("All tunnels already have MTU=%d", newMTU))
		return nil
	}

	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.SystemMTU, "failed to save config", err)
	}
	out.Success(fmt.Sprintf("MTU set to %d for %d tunnel(s)", newMTU, changed))

	out.Info("Restarting affected tunnel services...")
	for _, t := range affected {
		svcName := service.TunnelServiceName(t.Tag)
		_ = service.Stop(svcName)
		if err := transport.CreateService(t, cfg); err != nil {
			out.Warning(fmt.Sprintf("Failed to recreate %s: %s", svcName, err.Error()))
			continue
		}
		out.Success(fmt.Sprintf("  %s restarted", svcName))
	}

	return nil
}
