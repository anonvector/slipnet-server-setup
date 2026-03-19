package handlers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/binary"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/version"
)

func handleSystemUpdate(ctx *actions.Context) error {
	out := ctx.Output
	out.Info("Current version: " + version.String())
	out.Info("Downloading latest slipgate...")

	downloadURL := fmt.Sprintf("%s/latest/download/slipgate-%s-%s",
		"https://github.com/anonvector/slipgate/releases", runtime.GOOS, runtime.GOARCH)

	tmpPath, err := binary.Download(downloadURL)
	if err != nil {
		return actions.NewError(actions.SystemUpdate, "failed to download update", err)
	}
	defer os.Remove(tmpPath)

	execPath, err := os.Executable()
	if err != nil {
		return actions.NewError(actions.SystemUpdate, "failed to find current binary", err)
	}

	if runtime.GOOS == "linux" {
		if err := os.Rename(tmpPath, execPath); err != nil {
			cpCmd := exec.Command("cp", tmpPath, execPath)
			if err := cpCmd.Run(); err != nil {
				return actions.NewError(actions.SystemUpdate, "failed to replace binary", err)
			}
		}
		os.Chmod(execPath, 0755)
	}

	out.Success("slipgate updated")

	// Update transport binaries
	out.Print("")
	out.Info("Updating transport binaries...")

	transportBins := []string{"dnstt-server", "slipstream-server", "caddy-naive"}
	for _, name := range transportBins {
		binPath := filepath.Join(config.DefaultBinDir, name)
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			continue // not installed, skip
		}

		out.Info(fmt.Sprintf("  Updating %s...", name))

		// Remove old binary and re-download
		os.Remove(binPath)
		if err := binary.EnsureInstalled(name); err != nil {
			out.Warning(fmt.Sprintf("  Failed to update %s: %v", name, err))
			continue
		}
		out.Success(fmt.Sprintf("  %s updated", name))
	}

	// Migrate from microsocks to built-in SOCKS5 proxy
	microsocksPath := filepath.Join(config.DefaultBinDir, "microsocks")
	if _, err := os.Stat(microsocksPath); err == nil {
		out.Print("")
		out.Info("Migrating from microsocks to built-in SOCKS5 proxy...")
		cfg := ctx.Config.(*config.Config)

		// Determine listen mode and auth from existing config
		directSOCKS := false
		for _, t := range cfg.Tunnels {
			if t.Transport == config.TransportSOCKS {
				directSOCKS = true
			}
		}
		user, pass := "", ""
		if len(cfg.Users) > 0 {
			user = cfg.Users[0].Username
			pass = cfg.Users[0].Password
		}

		var setupErr error
		if directSOCKS {
			setupErr = proxy.SetupSOCKSExternal(user, pass)
		} else if user != "" {
			setupErr = proxy.SetupSOCKSWithAuth(user, pass)
		} else {
			setupErr = proxy.SetupSOCKS()
		}
		if setupErr != nil {
			out.Warning("Failed to migrate SOCKS5 proxy: " + setupErr.Error())
		} else {
			os.Remove(microsocksPath)
			out.Success("Migrated to built-in SOCKS5 proxy")
		}
	}

	// Restart all running slipgate services
	out.Print("")
	out.Info("Restarting services...")
	cfg := ctx.Config.(*config.Config)
	for _, t := range cfg.Tunnels {
		svcName := service.TunnelServiceName(t.Tag)
		if status, _ := service.Status(svcName); status != "" {
			if err := service.Restart(svcName); err != nil {
				out.Warning(fmt.Sprintf("Failed to restart %s: %v", svcName, err))
			} else {
				out.Success(fmt.Sprintf("  %s restarted", svcName))
			}
		}
	}
	for _, svc := range []string{"slipgate-dnsrouter", "slipgate-socks5"} {
		if status, _ := service.Status(svc); status != "" {
			if err := service.Restart(svc); err != nil {
				out.Warning(fmt.Sprintf("Failed to restart %s: %v", svc, err))
			} else {
				out.Success(fmt.Sprintf("  %s restarted", svc))
			}
		}
	}

	out.Print("")
	out.Success("Update complete!")
	return nil
}
