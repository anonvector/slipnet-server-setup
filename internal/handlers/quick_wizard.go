package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/binary"
	"github.com/anonvector/slipgate/internal/certs"
	"github.com/anonvector/slipgate/internal/clientcfg"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/dnsrouter"
	"github.com/anonvector/slipgate/internal/keys"
	"github.com/anonvector/slipgate/internal/network"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/system"
	"github.com/anonvector/slipgate/internal/transport"
)

func handleQuickWizard(ctx *actions.Context) error {
	out := ctx.Output

	if runtime.GOOS != "linux" {
		return actions.NewError(actions.QuickWizard, "slipgate only supports Linux servers", nil)
	}

	out.Print("")
	out.Print("  ── Quick Wizard ────────────────────────────────────")
	out.Print("")

	// 1. Pick transports (multi-select)
	selectedTransports, err := prompt.MultiSelect("Transports", actions.InstallTransportOptions)
	if err != nil {
		return err
	}
	if len(selectedTransports) == 0 {
		return actions.NewError(actions.QuickWizard, "at least one transport is required", nil)
	}

	// 2. Collect per-transport settings
	type transportSettings struct {
		transport  string
		backend    string
		backends   []string
		domain     string
		mtu        int
		recordType string
		naiveEmail string
		naiveDecoy string
		tlsPort    int
	}
	var allSettings []transportSettings

	for _, tr := range selectedTransports {
		out.Print("")
		out.Info(fmt.Sprintf("── %s settings ──", tr))

		isDirect := tr == config.TransportSSH || tr == config.TransportSOCKS || tr == config.TransportStunTLS

		var backend string
		var backends []string
		if isDirect {
			switch tr {
			case config.TransportSSH, config.TransportStunTLS:
				backend = config.BackendSSH
			case config.TransportSOCKS:
				backend = config.BackendSOCKS
			}
			backends = []string{backend}
		} else {
			backend, err = prompt.Select(fmt.Sprintf("Backend for %s", tr), actions.BackendOptions)
			if err != nil {
				return err
			}
			backends = []string{backend}
			if backend == "both" {
				backends = []string{config.BackendSOCKS, config.BackendSSH}
			}
		}

		domain := ""
		if !isDirect {
			domainHint := "t.example.com"
			if tr == config.TransportNaive {
				domainHint = "example.com"
			} else if tr == config.TransportSlipstream {
				domainHint = "s.example.com"
			} else if tr == config.TransportVayDNS {
				domainHint = "v.example.com"
			}
			displayName := tr
			if tr == config.TransportDNSTT {
				displayName = "dnstt/noizdns"
			}
			domain, err = prompt.String(fmt.Sprintf("Domain for %s (e.g. %s)", displayName, domainHint), "")
			if err != nil {
				return err
			}
			if domain == "" {
				return actions.NewError(actions.QuickWizard, fmt.Sprintf("domain is required for %s", tr), nil)
			}
		}

		mtu := config.DefaultMTU
		if tr == config.TransportDNSTT || tr == config.TransportVayDNS {
			mtuStr, err := prompt.String("MTU", fmt.Sprintf("%d", config.DefaultMTU))
			if err != nil {
				return err
			}
			if n, e := fmt.Sscanf(mtuStr, "%d", &mtu); n != 1 || e != nil {
				mtu = config.DefaultMTU
			}
		}

		var recordType string
		if tr == config.TransportVayDNS {
			rtOpts := make([]actions.SelectOption, len(config.ValidVayDNSRecordTypes))
			for i, rt := range config.ValidVayDNSRecordTypes {
				label := rt
				if i == 0 {
					label = rt + " (default)"
				}
				rtOpts[i] = actions.SelectOption{Value: rt, Label: label}
			}
			recordType, err = prompt.Select("DNS record type", rtOpts)
			if err != nil {
				return err
			}
		}

		var naiveEmail, naiveDecoy string
		if tr == config.TransportNaive {
			naiveEmail, err = prompt.String("Email (for Let's Encrypt)", "")
			if err != nil {
				return err
			}
			naiveDecoy, err = prompt.String("Decoy URL", config.RandomDecoyURL())
			if err != nil {
				return err
			}
		}

		tlsPort := 443
		if tr == config.TransportStunTLS {
			// Default to 8443 if NaiveProxy is also selected (it uses 443)
			defaultPort := "443"
			for _, other := range selectedTransports {
				if other == config.TransportNaive {
					defaultPort = "8443"
					break
				}
			}
			portStr, err := prompt.String("TLS listen port", defaultPort)
			if err != nil {
				return err
			}
			if n, e := fmt.Sscanf(portStr, "%d", &tlsPort); n != 1 || e != nil {
				tlsPort = 443
			}
		}

		allSettings = append(allSettings, transportSettings{
			transport:  tr,
			backend:    backend,
			backends:   backends,
			domain:     domain,
			mtu:        mtu,
			recordType: recordType,
			naiveEmail: naiveEmail,
			naiveDecoy: naiveDecoy,
			tlsPort:    tlsPort,
		})
	}

	// 3. Create user
	out.Print("")
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

	// ── Setup ──────────────────────────────────────────────────
	out.Print("")
	out.Info("Setting up...")

	// Check for existing dnstm installation
	if _, err := offerDnstmCleanup(out, actions.QuickWizard); err != nil {
		return err
	}

	// System user + dirs
	if err := system.EnsureUser(); err != nil {
		return actions.NewError(actions.QuickWizard, "failed to create system user", err)
	}
	for _, dir := range []string{config.DefaultConfigDir, config.DefaultTunnelDir} {
		if err := system.EnsureDir(dir, config.SystemUser); err != nil {
			return actions.NewError(actions.QuickWizard, fmt.Sprintf("failed to create %s", dir), err)
		}
	}

	// Download binaries
	downloadedBins := make(map[string]bool)
	for _, s := range allSettings {
		if bin, ok := config.TransportBinaries[s.transport]; ok && !downloadedBins[bin] {
			out.Info(fmt.Sprintf("Downloading %s...", bin))
			if err := binary.EnsureInstalled(bin); err != nil {
				return actions.NewError(actions.QuickWizard, fmt.Sprintf("failed to download %s", bin), err)
			}
			out.Success(fmt.Sprintf("%s ready", bin))
			downloadedBins[bin] = true
		}
	}

	// Firewall
	for _, s := range allSettings {
		switch s.transport {
		case config.TransportDNSTT, config.TransportSlipstream, config.TransportVayDNS:
			_ = network.AllowPort(53, "udp")
			_ = network.DisableResolvedStub()
		case config.TransportNaive:
			_ = network.AllowPort(80, "tcp")
			_ = network.AllowPort(443, "tcp")
		case config.TransportStunTLS:
			_ = network.AllowPort(s.tlsPort, "tcp")
		case config.TransportSSH:
			_ = network.AllowPort(22, "tcp")
		case config.TransportSOCKS:
			_ = network.AllowPort(1080, "tcp")
		}
	}

	// Load existing config or create defaults for fresh install
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.QuickWizard, "failed to write config", err)
		}
	}

	// ── Create tunnels ─────────────────────────────────────────
	var allTunnels []config.TunnelConfig
	needsSOCKS := false

	for _, s := range allSettings {
		var sharedDNSTTKey string
		var sharedDNSTTSrcDir string
		for _, b := range s.backends {
			tag := cfg.UniqueTag(s.transport)
			tunnelDomain := s.domain

			if s.backend == "both" {
				tag = cfg.UniqueTag(s.transport + "-" + b)
				if b == config.BackendSSH && s.transport != config.TransportNaive {
					parentDomain := baseDomain(s.domain)
					sshHint := "ts." + parentDomain
					if s.transport == config.TransportSlipstream {
						sshHint = "ss." + parentDomain
					} else if s.transport == config.TransportVayDNS {
						sshHint = "vs." + parentDomain
					}
					tunnelDomain, err = prompt.String(fmt.Sprintf("Domain for %s", tag), sshHint)
					if err != nil {
						return err
					}
				}
			}

			tunnel := config.TunnelConfig{
				Tag:       tag,
				Transport: s.transport,
				Backend:   b,
				Domain:    tunnelDomain,
				Enabled:   true,
			}

			if tunnel.IsDNSTunnel() {
				tunnel.Port = cfg.NextAvailablePort()
				for _, existing := range allTunnels {
					if existing.Port == tunnel.Port {
						tunnel.Port++
					}
				}
			}

			if err := cfg.ValidateNewTunnel(&tunnel); err != nil {
				out.Warning(fmt.Sprintf("Skip %s: %v", tag, err))
				continue
			}

			tunnelDir := config.TunnelDir(tag)
			if err := os.MkdirAll(tunnelDir, 0750); err != nil {
				return actions.NewError(actions.QuickWizard, "failed to create tunnel dir", err)
			}

			switch s.transport {
			case config.TransportDNSTT:
				privKeyPath := filepath.Join(tunnelDir, "server.key")
				pubKeyPath := filepath.Join(tunnelDir, "server.pub")

				if sharedDNSTTKey == "" {
					out.Info(fmt.Sprintf("Generating keypair for %s...", tunnelDomain))
					pubKey, err := keys.GenerateDNSTTKeys(privKeyPath, pubKeyPath)
					if err != nil {
						return actions.NewError(actions.QuickWizard, "key generation failed", err)
					}
					sharedDNSTTKey = pubKey
					sharedDNSTTSrcDir = tunnelDir
					out.Success(fmt.Sprintf("Public key: %s", pubKey))
				} else {
					if err := copyFile(filepath.Join(sharedDNSTTSrcDir, "server.key"), privKeyPath); err != nil {
						return actions.NewError(actions.QuickWizard, "failed to copy private key", err)
					}
					if err := copyFile(filepath.Join(sharedDNSTTSrcDir, "server.pub"), pubKeyPath); err != nil {
						return actions.NewError(actions.QuickWizard, "failed to copy public key", err)
					}
				}
				tunnel.DNSTT = &config.DNSTTConfig{
					MTU:        s.mtu,
					PrivateKey: privKeyPath,
					PublicKey:  sharedDNSTTKey,
				}

			case config.TransportVayDNS:
				privKeyPath := filepath.Join(tunnelDir, "server.key")
				pubKeyPath := filepath.Join(tunnelDir, "server.pub")

				if sharedDNSTTKey == "" {
					out.Info(fmt.Sprintf("Generating keypair for %s...", tunnelDomain))
					pubKey, err := keys.GenerateDNSTTKeys(privKeyPath, pubKeyPath)
					if err != nil {
						return actions.NewError(actions.QuickWizard, "key generation failed", err)
					}
					sharedDNSTTKey = pubKey
					sharedDNSTTSrcDir = tunnelDir
					out.Success(fmt.Sprintf("Public key: %s", pubKey))
				} else {
					if err := copyFile(filepath.Join(sharedDNSTTSrcDir, "server.key"), privKeyPath); err != nil {
						return actions.NewError(actions.QuickWizard, "failed to copy private key", err)
					}
					if err := copyFile(filepath.Join(sharedDNSTTSrcDir, "server.pub"), pubKeyPath); err != nil {
						return actions.NewError(actions.QuickWizard, "failed to copy public key", err)
					}
				}
				tunnel.VayDNS = &config.VayDNSConfig{
					MTU:        s.mtu,
					PrivateKey: privKeyPath,
					PublicKey:  sharedDNSTTKey,
					RecordType: s.recordType,
				}

			case config.TransportSlipstream:
				certPath := filepath.Join(tunnelDir, "cert.pem")
				keyPath := filepath.Join(tunnelDir, "key.pem")
				out.Info(fmt.Sprintf("Generating certificate for %s...", tunnelDomain))
				if err := certs.GenerateSelfSigned(certPath, keyPath, tunnelDomain); err != nil {
					return actions.NewError(actions.QuickWizard, "certificate generation failed", err)
				}
				tunnel.Slipstream = &config.SlipstreamConfig{
					Cert: certPath,
					Key:  keyPath,
				}

			case config.TransportStunTLS:
				certPath := filepath.Join(tunnelDir, "cert.pem")
				keyPath := filepath.Join(tunnelDir, "key.pem")
				out.Info("Generating self-signed TLS certificate...")
				if err := certs.GenerateSelfSigned(certPath, keyPath, tag); err != nil {
					return actions.NewError(actions.QuickWizard, "cert generation failed", err)
				}
				tunnel.StunTLS = &config.StunTLSConfig{
					Cert: certPath,
					Key:  keyPath,
					Port: s.tlsPort,
				}

			case config.TransportNaive:
				tunnel.Naive = &config.NaiveConfig{
					Email:    s.naiveEmail,
					DecoyURL: s.naiveDecoy,
					User:     username,
					Password: password,
					Port:     443,
				}
			}

			cfg.AddTunnel(tunnel)
			allTunnels = append(allTunnels, tunnel)

			if b == config.BackendSOCKS && s.transport != config.TransportNaive {
				needsSOCKS = true
			}
		}
	}

	if len(allTunnels) == 0 {
		return actions.NewError(actions.QuickWizard, "no tunnels created", nil)
	}

	// Save config
	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.QuickWizard, "failed to save config", err)
	}

	// Create SSH user
	if err := system.AddSSHUser(username, password); err != nil {
		out.Warning("Failed to create SSH user: " + err.Error())
	}
	cfg.AddUser(config.UserConfig{Username: username, Password: password})
	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.QuickWizard, "failed to save config", err)
	}
	out.Success(fmt.Sprintf("User %q created", username))

	// Check if any transport is direct SOCKS
	hasDirectSOCKS := false
	for _, s := range allSettings {
		if s.transport == config.TransportSOCKS {
			hasDirectSOCKS = true
		}
	}

	// Kill anything holding port 1080 before starting our SOCKS5 proxy
	if needsSOCKS || hasDirectSOCKS {
		network.FreePort(1080, "tcp")
	}

	// Setup SOCKS5 proxy
	if needsSOCKS {
		if err := proxy.SetupSOCKSWithAuth(username, password); err != nil {
			out.Warning("Failed to setup SOCKS5 proxy: " + err.Error())
		}
	}
	if hasDirectSOCKS {
		if err := proxy.SetupSOCKSExternal(username, password); err != nil {
			out.Warning("Failed to setup SOCKS5 proxy: " + err.Error())
		}
	}

	// Auto multi-mode when multiple DNS tunnels
	dnsTunnelCount := 0
	for _, t := range allTunnels {
		if t.IsDNSTunnel() {
			dnsTunnelCount++
		}
	}
	if dnsTunnelCount > 1 {
		cfg.Route.Mode = "multi"
		_ = cfg.Save()
	}

	// Start tunnel services
	for i := range allTunnels {
		if allTunnels[i].IsDNSTunnel() && allTunnels[i].Port > 0 {
			network.FreePort(allTunnels[i].Port, "udp")
		}
		out.Info(fmt.Sprintf("Starting %s...", allTunnels[i].Tag))
		if err := transport.CreateService(&allTunnels[i], cfg); err != nil {
			return actions.NewError(actions.QuickWizard, fmt.Sprintf("failed to start %s", allTunnels[i].Tag), err)
		}
		out.Success(fmt.Sprintf("Tunnel %q running", allTunnels[i].Tag))
	}

	// Start DNS router to forward port 53 to internal tunnel ports
	if dnsTunnelCount > 0 {
		network.FreePort(53, "udp")
		out.Info("Starting DNS router...")
		if err := dnsrouter.CreateRouterService(); err != nil {
			out.Warning("Failed to create DNS router: " + err.Error())
		} else if err := dnsrouter.RestartRouterService(); err != nil {
			out.Warning("Failed to start DNS router: " + err.Error())
		} else {
			out.Success("DNS router started")
		}
	}

	// ── Summary ────────────────────────────────────────────────
	out.Print("")
	out.Print("  ══════════════════════════════════════════════════════")
	out.Print("    Quick Wizard Complete")
	out.Print("  ══════════════════════════════════════════════════════")
	out.Print("")

	for _, t := range allTunnels {
		out.Print(fmt.Sprintf("    Tunnel : %s (backend: %s)", t.Tag, t.Backend))
	}
	out.Print(fmt.Sprintf("    User   : %s / %s", username, password))

	if allTunnels[0].DNSTT != nil {
		out.Print(fmt.Sprintf("    PubKey : %s", allTunnels[0].DNSTT.PublicKey))
		out.Print(fmt.Sprintf("    MTU    : %d", allTunnels[0].DNSTT.MTU))
	} else if allTunnels[0].VayDNS != nil {
		out.Print(fmt.Sprintf("    PubKey : %s", allTunnels[0].VayDNS.PublicKey))
		out.Print(fmt.Sprintf("    MTU    : %d", allTunnels[0].VayDNS.MTU))
	}

	// DNS records
	out.Print("")
	out.Print("    DNS Records Required:")
	shownRecords := make(map[string]bool)
	for _, t := range allTunnels {
		if t.IsDirectTransport() {
			continue
		}
		if t.Transport == config.TransportNaive {
			rec := fmt.Sprintf("A:%s", t.Domain)
			if !shownRecords[rec] {
				shownRecords[rec] = true
				out.Print(fmt.Sprintf("      A  record: %s → your server IP", t.Domain))
			}
		} else {
			aRec := fmt.Sprintf("A:ns.%s", baseDomain(t.Domain))
			if !shownRecords[aRec] {
				shownRecords[aRec] = true
				out.Print(fmt.Sprintf("      A  record: ns.%s → your server IP", baseDomain(t.Domain)))
			}
			nsRec := fmt.Sprintf("NS:%s", t.Domain)
			if !shownRecords[nsRec] {
				shownRecords[nsRec] = true
				out.Print(fmt.Sprintf("      NS record: %s → ns.%s", t.Domain, baseDomain(t.Domain)))
			}
		}
	}

	// Client configs
	out.Print("")
	out.Print("    Client Configs:")
	out.Print("")
	for _, t := range allTunnels {
		backendCfg := cfg.GetBackend(t.Backend)
		if backendCfg == nil {
			continue
		}
		modes := []string{""}
		if t.Transport == config.TransportDNSTT {
			modes = []string{clientcfg.ClientModeDNSTT, clientcfg.ClientModeNoizDNS}
		}
		for _, mode := range modes {
			opts := clientcfg.URIOptions{
				ClientMode: mode,
				Username:   username,
				Password:   password,
			}
			uri, uriErr := clientcfg.GenerateURI(&t, backendCfg, cfg, opts)
			if uriErr != nil {
				continue
			}
			label := t.Tag
			if mode == clientcfg.ClientModeNoizDNS {
				label = strings.ReplaceAll(label, "dnstt", "noizdns")
			}
			out.Print(fmt.Sprintf("    [%s] %s", label, username))
			out.Print(fmt.Sprintf("    %s", uri))
			out.Print("")
		}
	}

	out.Print("  ══════════════════════════════════════════════════════")
	out.Print("")

	return nil
}
