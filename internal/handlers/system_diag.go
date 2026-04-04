package handlers

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/version"
)

func handleSystemDiag(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output

	out.Print("")
	out.Print("  SlipGate Diagnostics")
	out.Print("  " + version.String())
	out.Print("  ────────────────────────────────────────")

	pass := 0
	warn := 0
	fail := 0

	check := func(label string, ok bool, detail string) {
		if ok {
			pass++
			out.Success(fmt.Sprintf("%-40s %s", label, detail))
		} else {
			fail++
			out.Error(fmt.Sprintf("%-40s %s", label, detail))
		}
	}

	info := func(label string, detail string) {
		warn++
		out.Warning(fmt.Sprintf("%-40s %s", label, detail))
	}

	// ── System ──────────────────────────────────────────────
	out.Print("")
	out.Print("  System")
	out.Print("  ──────")

	// System user
	_, err := user.Lookup(config.SystemUser)
	check("System user (slipgate)", err == nil, boolStr(err == nil, "exists", "missing — run install"))

	// Config directory
	_, err = os.Stat(config.DefaultConfigDir)
	check("Config directory", err == nil, config.DefaultConfigDir)

	// Tunnel directory
	_, err = os.Stat(config.DefaultTunnelDir)
	check("Tunnel directory", err == nil, config.DefaultTunnelDir)

	// Config file
	_, cfgErr := config.Load()
	check("Config file", cfgErr == nil, boolStr(cfgErr == nil, "valid", fmt.Sprintf("error: %v", cfgErr)))

	// systemd-resolved stub
	stubDisabled := isResolvedStubDisabled()
	hasDNSTunnels := false
	for _, t := range cfg.Tunnels {
		if t.IsDNSTunnel() {
			hasDNSTunnels = true
			break
		}
	}
	if hasDNSTunnels {
		check("systemd-resolved stub", stubDisabled, boolStr(stubDisabled, "disabled", "still active — port 53 conflict"))
	}

	// ── Tunnels ─────────────────────────────────────────────
	out.Print("")
	out.Print(fmt.Sprintf("  Tunnels (%d configured)", len(cfg.Tunnels)))
	out.Print("  ───────")

	if len(cfg.Tunnels) == 0 {
		info("No tunnels configured", "run install or tunnel add")
	}

	for _, t := range cfg.Tunnels {
		// Direct transports use system services (sshd, microsocks), not slipgate-managed ones
		if t.IsDirectTransport() {
			continue
		}

		tag := t.Tag

		// Service status
		svcName := service.TunnelServiceName(tag)
		svcExists := service.Exists(svcName)
		status := "missing"
		if svcExists {
			status, _ = service.Status(svcName)
		}

		svcOK := status == "active"
		check(fmt.Sprintf("[%s] service", tag), svcOK,
			boolStr(svcOK, "active", status))

		if svcExists && !svcOK {
			showRecentLogs(out, svcName)
		}

		// Service enabled (survives reboot)
		if svcExists {
			enabled := isServiceEnabled(svcName)
			check(fmt.Sprintf("[%s] enabled at boot", tag), enabled,
				boolStr(enabled, "yes", "no — will not start after reboot"))
		}

		// Tunnel directory
		tunnelDir := config.TunnelDir(tag)
		_, err := os.Stat(tunnelDir)
		check(fmt.Sprintf("[%s] tunnel directory", tag), err == nil, tunnelDir)

		// Transport-specific file checks
		switch t.Transport {
		case config.TransportDNSTT:
			if t.DNSTT != nil {
				checkFileExists(check, tag, "private key", t.DNSTT.PrivateKey)
			}
		case config.TransportVayDNS:
			if t.VayDNS != nil {
				checkFileExists(check, tag, "private key", t.VayDNS.PrivateKey)
			}
		case config.TransportSlipstream:
			if t.Slipstream != nil {
				checkFileExists(check, tag, "certificate", t.Slipstream.Cert)
				checkFileExists(check, tag, "key", t.Slipstream.Key)
			}
		}

		// Port check for DNS tunnels
		if t.IsDNSTunnel() && t.Port > 0 {
			portOK := isPortListening(t.Port, "udp")
			check(fmt.Sprintf("[%s] port %d/udp", tag, t.Port), portOK,
				boolStr(portOK, "listening", "not listening"))
		}
	}

	// ── Services ────────────────────────────────────────────
	out.Print("")
	out.Print("  Infrastructure Services")
	out.Print("  ───────────────────────")

	// DNS router
	if hasDNSTunnels {
		routerExists := service.Exists("slipgate-dnsrouter")
		if routerExists {
			status, _ := service.Status("slipgate-dnsrouter")
			routerOK := status == "active"
			check("DNS router service", routerOK,
				boolStr(routerOK, "active", status))
			if !routerOK {
				showRecentLogs(out, "slipgate-dnsrouter")
			}

			enabled := isServiceEnabled("slipgate-dnsrouter")
			check("DNS router enabled at boot", enabled,
				boolStr(enabled, "yes", "no — will not start after reboot"))
		} else {
			check("DNS router service", false, "not installed")
		}

		port53OK := isPortListening(53, "udp")
		check("Port 53/udp", port53OK,
			boolStr(port53OK, "listening", "not listening — DNS tunnels unreachable"))
	}

	// SOCKS5 proxy
	socksExists := service.Exists("slipgate-socks5")
	if socksExists {
		status, _ := service.Status("slipgate-socks5")
		socksOK := status == "active"
		check("SOCKS5 proxy service", socksOK,
			boolStr(socksOK, "active", status))
		if !socksOK {
			showRecentLogs(out, "slipgate-socks5")
		}

		port1080OK := isPortListening(1080, "tcp")
		check("Port 1080/tcp", port1080OK,
			boolStr(port1080OK, "listening", "not listening"))
	}

	// WARP
	if cfg.Warp.Enabled {
		warpExists := service.Exists("slipgate-warp")
		if warpExists {
			status, _ := service.Status("slipgate-warp")
			warpOK := status == "active"
			check("WARP service", warpOK,
				boolStr(warpOK, "active", status))
			if !warpOK {
				showRecentLogs(out, "slipgate-warp")
			}
		} else {
			check("WARP service", false, "enabled in config but service missing")
		}
	}

	// ── DNS Resolution ──────────────────────────────────────
	domainsChecked := false
	for _, t := range cfg.Tunnels {
		if t.Domain == "" || t.IsDirectTransport() {
			continue
		}
		if !domainsChecked {
			out.Print("")
			out.Print("  DNS Resolution")
			out.Print("  ──────────────")
			domainsChecked = true
		}
		if t.IsDNSTunnel() {
			// DNS tunnels use NS records, not A records
			nss, err := net.LookupNS(t.Domain)
			if err != nil || len(nss) == 0 {
				check(fmt.Sprintf("[%s] %s NS", t.Tag, t.Domain), false, "NS record not found")
			} else {
				nsHost := nss[0].Host
				check(fmt.Sprintf("[%s] %s NS", t.Tag, t.Domain), true, nsHost)
				// Verify the nameserver resolves to an IP
				addrs, err := net.LookupHost(strings.TrimSuffix(nsHost, "."))
				if err != nil {
					check(fmt.Sprintf("[%s] %s A", t.Tag, strings.TrimSuffix(nsHost, ".")), false, "not resolving")
				} else {
					check(fmt.Sprintf("[%s] %s A", t.Tag, strings.TrimSuffix(nsHost, ".")), true, strings.Join(addrs, ", "))
				}
			}
		} else {
			addrs, err := net.LookupHost(t.Domain)
			if err != nil {
				check(fmt.Sprintf("[%s] %s", t.Tag, t.Domain), false, "not resolving")
			} else {
				check(fmt.Sprintf("[%s] %s", t.Tag, t.Domain), true, strings.Join(addrs, ", "))
			}
		}
	}

	// ── Orphaned Services ───────────────────────────────────
	allSvc := service.ListSlipgateServices()
	knownSvc := map[string]bool{
		"slipgate-dnsrouter": true,
		"slipgate-socks5":    true,
		"slipgate-warp":      true,
	}
	for _, t := range cfg.Tunnels {
		knownSvc[service.TunnelServiceName(t.Tag)] = true
	}
	var orphaned []string
	for _, svc := range allSvc {
		if !knownSvc[svc] {
			orphaned = append(orphaned, svc)
		}
	}
	if len(orphaned) > 0 {
		out.Print("")
		out.Print("  Orphaned Services")
		out.Print("  ─────────────────")
		for _, svc := range orphaned {
			info(svc, "service exists but not in config")
		}
	}

	// ── Summary ─────────────────────────────────────────────
	out.Print("")
	out.Print("  ────────────────────────────────────────")
	out.Print(fmt.Sprintf("  Results: %d passed, %d warnings, %d failed", pass, warn, fail))
	out.Print("")

	return nil
}

func showRecentLogs(out actions.OutputWriter, svcName string) {
	logs, err := service.Logs(svcName, "10")
	if err != nil || strings.TrimSpace(logs) == "" {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		out.Print(fmt.Sprintf("         %s", line))
	}
}

func checkFileExists(check func(string, bool, string), tag, label, path string) {
	_, err := os.Stat(path)
	check(fmt.Sprintf("[%s] %s", tag, label), err == nil,
		boolStr(err == nil, filepath.Base(path), "missing: "+path))
}

func boolStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

func isResolvedStubDisabled() bool {
	data, err := os.ReadFile("/etc/systemd/resolved.conf.d/slipgate-no-stub.conf")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "DNSStubListener=no")
}

func isServiceEnabled(name string) bool {
	out, err := exec.Command("systemctl", "is-enabled", name+".service").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "enabled"
}

func isPortListening(port int, proto string) bool {
	switch proto {
	case "tcp":
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1e9)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	case "udp":
		// For UDP, check if we can bind — if we can, nothing is listening
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return false
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			// Can't bind = something is already listening = good
			return true
		}
		conn.Close()
		return false
	}
	return false
}
