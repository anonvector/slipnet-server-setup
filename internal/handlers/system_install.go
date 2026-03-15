package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/binary"
	"github.com/anonvector/slipgate/internal/certs"
	"github.com/anonvector/slipgate/internal/clientcfg"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/keys"
	"github.com/anonvector/slipgate/internal/network"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/router"
	"github.com/anonvector/slipgate/internal/system"
	"github.com/anonvector/slipgate/internal/transport"
)

func handleSystemInstall(ctx *actions.Context) error {
	out := ctx.Output

	if runtime.GOOS != "linux" {
		return actions.NewError(actions.SystemInstall, "slipgate only supports Linux servers", nil)
	}

	// ── Step 1: Select transports ──────────────────────────────────
	out.Print("")
	out.Print("  Which transports do you want to install?")

	transports, err := prompt.MultiSelect("Transports", actions.TransportOptions)
	if err != nil {
		return err
	}
	if len(transports) == 0 {
		return actions.NewError(actions.SystemInstall, "no transports selected", nil)
	}

	// ── Step 2: Create system user and directories ─────────────────
	out.Info("Creating system user 'slipgate'...")
	if err := system.EnsureUser(); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to create system user", err)
	}

	for _, dir := range []string{config.DefaultConfigDir, config.DefaultTunnelDir} {
		if err := system.EnsureDir(dir, config.SystemUser); err != nil {
			return actions.NewError(actions.SystemInstall, fmt.Sprintf("failed to create %s", dir), err)
		}
	}

	// ── Step 3: Download binaries ──────────────────────────────────
	out.Info("Downloading binaries...")
	needsSOCKS := false
	for _, t := range transports {
		bin, ok := config.TransportBinaries[t]
		if !ok {
			continue
		}
		out.Info(fmt.Sprintf("  Downloading %s...", bin))
		if err := binary.EnsureInstalled(bin); err != nil {
			return actions.NewError(actions.SystemInstall, fmt.Sprintf("failed to download %s", bin), err)
		}
		out.Success(fmt.Sprintf("  %s (%s/%s)", bin, runtime.GOOS, runtime.GOARCH))

		if t != config.TransportNaive {
			needsSOCKS = true
		}
	}

	if needsSOCKS {
		out.Info("  Downloading microsocks...")
		if err := binary.EnsureInstalled("microsocks"); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to download microsocks", err)
		}
		out.Success("  microsocks")
	}

	// ── Step 4: Configure firewall ─────────────────────────────────
	out.Info("Configuring firewall...")
	needsDNS := false
	needsHTTPS := false
	for _, t := range transports {
		switch t {
		case config.TransportDNSTT, config.TransportSlipstream:
			needsDNS = true
		case config.TransportNaive:
			needsHTTPS = true
		}
	}
	if needsDNS {
		if err := network.AllowPort(53, "udp"); err != nil {
			out.Warning("Failed to open port 53/udp: " + err.Error())
		}
	}
	if needsHTTPS {
		if err := network.AllowPort(443, "tcp"); err != nil {
			out.Warning("Failed to open port 443/tcp: " + err.Error())
		}
	}

	// Write default config
	cfg := config.Default()
	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to write config", err)
	}

	out.Print("")
	out.Success("Dependencies installed!")

	// ── Step 5: Set up first tunnel ────────────────────────────────
	out.Print("")
	out.Print("  ── First Tunnel Setup ──────────────────────────────")
	out.Print("")

	setupTunnel, err := prompt.Confirm("Set up your first tunnel now?")
	if err != nil {
		return err
	}
	if !setupTunnel {
		out.Print("")
		out.Info("Run 'sudo slipgate tunnel add' when you're ready.")
		return nil
	}

	// Pick transport (from the ones they installed)
	var transportOptions []actions.SelectOption
	for _, opt := range actions.TransportOptions {
		for _, t := range transports {
			if opt.Value == t {
				transportOptions = append(transportOptions, opt)
			}
		}
	}

	selectedTransport := transports[0]
	if len(transportOptions) > 1 {
		selectedTransport, err = prompt.Select("Transport for this tunnel", transportOptions)
		if err != nil {
			return err
		}
	}

	// Backend
	backend, err := prompt.Select("Backend", actions.BackendOptions)
	if err != nil {
		return err
	}

	// Tag
	tag, err := prompt.String("Tunnel name (tag)", "tunnel1")
	if err != nil {
		return err
	}

	// Domain
	domain, err := prompt.String("Domain (e.g. t.example.com)", "")
	if err != nil {
		return err
	}
	if domain == "" {
		return actions.NewError(actions.SystemInstall, "domain is required", nil)
	}

	// MTU (for DNS tunnels)
	mtu := config.DefaultMTU

	tunnel := config.TunnelConfig{
		Tag:       tag,
		Transport: selectedTransport,
		Backend:   backend,
		Domain:    domain,
		Enabled:   true,
	}

	if tunnel.IsDNSTunnel() {
		tunnel.Port = cfg.NextAvailablePort()
	}

	if err := cfg.ValidateNewTunnel(&tunnel); err != nil {
		return actions.NewError(actions.SystemInstall, "validation failed", err)
	}

	// Create tunnel directory
	tunnelDir := config.TunnelDir(tag)
	if err := os.MkdirAll(tunnelDir, 0750); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to create tunnel dir", err)
	}

	// Transport-specific setup
	switch selectedTransport {
	case config.TransportDNSTT:
		privKeyPath := filepath.Join(tunnelDir, "server.key")
		pubKeyPath := filepath.Join(tunnelDir, "server.pub")
		out.Info("Generating Curve25519 keypair...")
		pubKey, err := keys.GenerateDNSTTKeys(privKeyPath, pubKeyPath)
		if err != nil {
			return actions.NewError(actions.SystemInstall, "key generation failed", err)
		}
		tunnel.DNSTT = &config.DNSTTConfig{
			MTU:        mtu,
			PrivateKey: privKeyPath,
			PublicKey:   pubKey,
		}
		out.Success(fmt.Sprintf("Public key: %s", pubKey))

	case config.TransportSlipstream:
		certPath := filepath.Join(tunnelDir, "cert.pem")
		keyPath := filepath.Join(tunnelDir, "key.pem")
		out.Info("Generating self-signed certificate...")
		if err := certs.GenerateSelfSigned(certPath, keyPath, domain); err != nil {
			return actions.NewError(actions.SystemInstall, "cert generation failed", err)
		}
		tunnel.Slipstream = &config.SlipstreamConfig{
			Cert: certPath,
			Key:  keyPath,
		}

	case config.TransportNaive:
		email, err := prompt.String("Email (for Let's Encrypt)", "")
		if err != nil {
			return err
		}
		decoyURL, err := prompt.String("Decoy URL", "https://www.wikipedia.org")
		if err != nil {
			return err
		}
		tunnel.Naive = &config.NaiveConfig{
			Email:    email,
			DecoyURL: decoyURL,
			Port:     443,
		}
	}

	// Save tunnel to config
	cfg.AddTunnel(tunnel)
	cfg.Route.Active = tag
	cfg.Route.Default = tag
	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to save config", err)
	}

	// Create and start systemd service
	out.Info("Creating systemd service...")
	if err := transport.CreateService(&tunnel, cfg); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to create service", err)
	}

	// Setup microsocks if SOCKS backend
	if needsSOCKS && backend == config.BackendSOCKS {
		if err := proxy.SetupMicrosocks(); err != nil {
			out.Warning("Failed to setup microsocks: " + err.Error())
		}
	}

	if err := router.AddTunnel(cfg, &tunnel); err != nil {
		out.Warning("Failed to register with router: " + err.Error())
	}

	out.Success(fmt.Sprintf("Tunnel %q created and started!", tag))

	// ── Step 6: Create first user ──────────────────────────────────
	out.Print("")
	out.Print("  ── User Setup ──────────────────────────────────────")
	out.Print("")

	createUser, err := prompt.Confirm("Create a user now?")
	if err != nil {
		return err
	}
	if createUser {
		username, err := prompt.String("Username", "user1")
		if err != nil {
			return err
		}
		password, err := prompt.String("Password (leave blank to generate)", "")
		if err != nil {
			return err
		}
		if password == "" {
			password = system.GeneratePassword(16)
			out.Info(fmt.Sprintf("Generated password: %s", password))
		}

		if err := system.AddSSHUser(username, password); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to create user", err)
		}

		if err := proxy.SetupMicrosocksWithAuth(username, password); err != nil {
			out.Warning("Failed to update SOCKS proxy auth: " + err.Error())
		}

		cfg.AddUser(config.UserConfig{Username: username, Password: password})
		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to save config", err)
		}

		out.Success(fmt.Sprintf("User %q created (SSH + SOCKS)", username))
	}

	// ── Step 7: Summary ────────────────────────────────────────────
	out.Print("")
	out.Print("  ══════════════════════════════════════════════════════")
	out.Print("    Installation Summary")
	out.Print("  ══════════════════════════════════════════════════════")
	out.Print("")
	out.Print(fmt.Sprintf("    Transport : %s", selectedTransport))
	out.Print(fmt.Sprintf("    Backend   : %s", backend))
	out.Print(fmt.Sprintf("    Domain    : %s", domain))
	out.Print(fmt.Sprintf("    Tag       : %s", tag))

	if tunnel.DNSTT != nil {
		out.Print(fmt.Sprintf("    Public Key: %s", tunnel.DNSTT.PublicKey))
		out.Print(fmt.Sprintf("    MTU       : %d", tunnel.DNSTT.MTU))
	}

	out.Print("")
	out.Print("    DNS Records Required:")
	out.Print(fmt.Sprintf("      A  record: ns.%s → your server IP", baseDomain(domain)))
	out.Print(fmt.Sprintf("      NS record: %s → ns.%s", domain, baseDomain(domain)))
	out.Print("")

	// Show slipnet:// configs
	if len(cfg.Users) > 0 {
		out.Print("    Client Configs:")
		out.Print("")
		for _, u := range cfg.Users {
			backendCfg := cfg.GetBackend(tunnel.Backend)
			if backendCfg == nil {
				continue
			}

			modes := []string{""}
			if tunnel.Transport == config.TransportDNSTT {
				modes = []string{clientcfg.ClientModeDNSTT, clientcfg.ClientModeNoizDNS}
			}

			for _, mode := range modes {
				opts := clientcfg.URIOptions{
					ClientMode: mode,
					Username:   u.Username,
					Password:   u.Password,
				}
				uri, err := clientcfg.GenerateURI(&tunnel, backendCfg, cfg, opts)
				if err != nil {
					continue
				}
				label := tag
				if mode != "" {
					label += " (" + mode + ")"
				}
				out.Print(fmt.Sprintf("    [%s] %s", label, u.Username))
				out.Print(fmt.Sprintf("    %s", uri))
				out.Print("")
			}
		}
	}

	out.Print("  ══════════════════════════════════════════════════════")
	out.Print("")
	out.Print("  Next steps:")
	out.Print("    - Set up DNS records above with your domain registrar")
	out.Print("    - Import the slipnet:// config into the SlipNet app")
	out.Print("    - Add more tunnels: sudo slipgate tunnel add")
	out.Print("    - Add more users:   sudo slipgate users")
	out.Print("")

	return nil
}

// baseDomain extracts the parent domain from a subdomain.
// e.g. "t.example.com" → "example.com"
func baseDomain(domain string) string {
	parts := splitDomain(domain)
	if len(parts) <= 2 {
		return domain
	}
	return joinDomain(parts[1:])
}

func splitDomain(d string) []string {
	var parts []string
	for _, p := range splitBy(d, '.') {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func splitBy(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func joinDomain(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "."
		}
		result += p
	}
	return result
}
