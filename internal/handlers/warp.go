package handlers

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/transport"
	"github.com/anonvector/slipgate/internal/warp"
)

func handleWarp(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output

	if !warp.IsSetUp() {
		ok, err := prompt.Confirm("WARP is not configured. Set it up now?")
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}

		out.Info("Setting up Cloudflare WARP...")
		if err := warp.Setup(cfg, func(msg string) { out.Info(msg) }); err != nil {
			return actions.NewError(actions.WarpToggle, "WARP setup failed", err)
		}
		out.Success("WARP configured")

		if err := warp.Enable(); err != nil {
			return actions.NewError(actions.WarpToggle, "failed to start WARP", err)
		}
		cfg.Warp.Enabled = true
		if err := cfg.Save(); err != nil {
			out.Warning("Failed to save config: " + err.Error())
		}

		recreateProxies(cfg, true, out)
		out.Success("WARP enabled — tunnel user traffic now routes through Cloudflare")
		return nil
	}

	// Already set up — show status and offer toggle
	if warp.IsRunning() {
		out.Info("WARP is currently ENABLED (active)")
	} else {
		out.Info("WARP is currently DISABLED (inactive)")
	}

	action, err := prompt.Select("Action", []actions.SelectOption{
		{Value: "enable", Label: "Enable WARP"},
		{Value: "disable", Label: "Disable WARP"},
		{Value: "cancel", Label: "Cancel"},
	})
	if err != nil {
		return err
	}

	switch action {
	case "enable":
		if err := warp.RefreshRouting(cfg); err != nil {
			out.Warning("Failed to refresh routing: " + err.Error())
		}
		if err := warp.Enable(); err != nil {
			return actions.NewError(actions.WarpToggle, "failed to start WARP", err)
		}
		cfg.Warp.Enabled = true
		if err := cfg.Save(); err != nil {
			out.Warning("Failed to save config: " + err.Error())
		}
		recreateProxies(cfg, true, out)
		out.Success("WARP enabled")

	case "disable":
		if err := warp.Disable(); err != nil {
			return actions.NewError(actions.WarpToggle, "failed to stop WARP", err)
		}
		cfg.Warp.Enabled = false
		if err := cfg.Save(); err != nil {
			out.Warning("Failed to save config: " + err.Error())
		}
		recreateProxies(cfg, false, out)
		out.Success("WARP disabled")
	}

	return nil
}

// recreateProxies restarts the SOCKS5 proxy and NaiveProxy services
// under the appropriate user after a WARP toggle.
func recreateProxies(cfg *config.Config, warpEnabled bool, out actions.OutputWriter) {
	// SOCKS proxy
	if warpEnabled {
		proxy.RunAsUser = warp.SocksUser
	} else {
		proxy.RunAsUser = ""
	}
	if len(cfg.Users) > 0 {
		if err := proxy.SetupSOCKSWithUsers(cfg.Users); err != nil {
			out.Warning("Failed to update SOCKS proxy: " + err.Error())
		}
	} else {
		if err := proxy.SetupSOCKS(); err != nil {
			out.Warning("Failed to update SOCKS proxy: " + err.Error())
		}
	}

	// NaiveProxy tunnels — recreate so Caddy runs under the right user
	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].Transport == config.TransportNaive {
			out.Info(fmt.Sprintf("Updating NaiveProxy %q...", cfg.Tunnels[i].Tag))
			if err := transport.CreateService(&cfg.Tunnels[i], cfg); err != nil {
				out.Warning(fmt.Sprintf("Failed to update %s: %s", cfg.Tunnels[i].Tag, err.Error()))
			}
		}
	}
}
