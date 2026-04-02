package handlers

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/certs"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/keys"
	"github.com/anonvector/slipgate/internal/network"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/router"
	"github.com/anonvector/slipgate/internal/transport"
)

func handleTunnelAdd(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output

	transport_ := ctx.GetArg("transport")
	backend := ctx.GetArg("backend")
	tag := ctx.GetArg("tag")
	domain := ctx.GetArg("domain")

	// Interactive prompts for missing fields
	if transport_ == "" {
		var err error
		transport_, err = prompt.Select("Transport", actions.TransportOptions)
		if err != nil {
			return err
		}
	}
	// Direct transports have an implicit backend
	isDirect := transport_ == config.TransportSSH || transport_ == config.TransportSOCKS
	if isDirect {
		switch transport_ {
		case config.TransportSSH:
			backend = config.BackendSSH
		case config.TransportSOCKS:
			backend = config.BackendSOCKS
		}
	}
	if backend == "" {
		var err error
		backend, err = prompt.Select("Backend", actions.BackendOptions)
		if err != nil {
			return err
		}
	}
	if tag == "" {
		var err error
		tag, err = prompt.String("Tag (unique name)", "")
		if err != nil {
			return err
		}
	}
	if !isDirect && domain == "" {
		var err error
		domain, err = prompt.String("Domain", "")
		if err != nil {
			return err
		}
	}

	// Expand "both" into socks + ssh
	backends := []string{backend}
	if backend == "both" {
		backends = []string{config.BackendSOCKS, config.BackendSSH}
	}

	for _, b := range backends {
		tunnelTag := tag
		tunnelDomain := domain

		if backend == "both" {
			tunnelTag = tag + "-" + b
			// SSH backend needs its own subdomain for DNS tunnels
			if b == config.BackendSSH && transport_ != config.TransportNaive {
				parentDomain := baseDomain(domain)
				sshHint := "ts." + parentDomain
				if transport_ == config.TransportSlipstream {
					sshHint = "ss." + parentDomain
				} else if transport_ == config.TransportVayDNS {
					sshHint = "vs." + parentDomain
				}
				sshDomain, err := prompt.String(fmt.Sprintf("Domain for %s", tunnelTag), sshHint)
				if err != nil {
					return err
				}
				tunnelDomain = sshDomain
			}
		}

		if err := addSingleTunnel(ctx, cfg, transport_, b, tunnelTag, tunnelDomain); err != nil {
			out.Warning(fmt.Sprintf("Failed to add %s: %v", tunnelTag, err))
		}
	}

	return nil
}

func addSingleTunnel(ctx *actions.Context, cfg *config.Config, transport_, backend, tag, domain string) error {
	out := ctx.Output

	tunnel := config.TunnelConfig{
		Tag:       tag,
		Transport: transport_,
		Backend:   backend,
		Domain:    domain,
		Enabled:   true,
	}

	// Assign port for DNS tunnels
	if tunnel.IsDNSTunnel() {
		tunnel.Port = cfg.NextAvailablePort()
	}

	// Validate
	if err := cfg.ValidateNewTunnel(&tunnel); err != nil {
		return actions.NewError(actions.TunnelAdd, "validation failed", err)
	}

	// Create tunnel directory
	tunnelDir := config.TunnelDir(tag)
	if err := os.MkdirAll(tunnelDir, 0750); err != nil {
		return actions.NewError(actions.TunnelAdd, "failed to create tunnel dir", err)
	}

	// Transport-specific setup
	switch transport_ {
	case config.TransportDNSTT:
		privKeyPath := filepath.Join(tunnelDir, "server.key")
		pubKeyPath := filepath.Join(tunnelDir, "server.pub")

		privKeyHex := ctx.GetArg("private-key")
		pubKeyHex := ctx.GetArg("public-key")

		var pubKey string
		var err error

		switch {
		case privKeyHex != "" && pubKeyHex != "":
			out.Info("Importing provided keypair...")
			pubKey, err = keys.ImportDNSTTKeyPair(privKeyHex, pubKeyHex, privKeyPath, pubKeyPath)
		case privKeyHex != "":
			out.Info("Importing private key and deriving public key...")
			pubKey, err = keys.ImportDNSTTKeys(privKeyHex, privKeyPath, pubKeyPath)
		default:
			out.Info("Generating Curve25519 keypair...")
			pubKey, err = keys.GenerateDNSTTKeys(privKeyPath, pubKeyPath)
		}
		if err != nil {
			return actions.NewError(actions.TunnelAdd, "key setup failed", err)
		}

		tunnel.DNSTT = &config.DNSTTConfig{
			MTU:        config.DefaultMTU,
			PrivateKey: privKeyPath,
			PublicKey:  pubKey,
		}
		out.Success(fmt.Sprintf("Public key: %s", pubKey))

	case config.TransportSlipstream:
		certPath := filepath.Join(tunnelDir, "cert.pem")
		keyPath := filepath.Join(tunnelDir, "key.pem")
		out.Info("Generating self-signed certificate...")
		if err := certs.GenerateSelfSigned(certPath, keyPath, domain); err != nil {
			return actions.NewError(actions.TunnelAdd, "cert generation failed", err)
		}
		tunnel.Slipstream = &config.SlipstreamConfig{
			Cert: certPath,
			Key:  keyPath,
		}

	case config.TransportVayDNS:
		privKeyPath := filepath.Join(tunnelDir, "server.key")
		pubKeyPath := filepath.Join(tunnelDir, "server.pub")

		privKeyHex := ctx.GetArg("private-key")
		pubKeyHex := ctx.GetArg("public-key")

		var pubKey string
		var err error

		switch {
		case privKeyHex != "" && pubKeyHex != "":
			out.Info("Importing provided keypair...")
			pubKey, err = keys.ImportDNSTTKeyPair(privKeyHex, pubKeyHex, privKeyPath, pubKeyPath)
		case privKeyHex != "":
			out.Info("Importing private key and deriving public key...")
			pubKey, err = keys.ImportDNSTTKeys(privKeyHex, privKeyPath, pubKeyPath)
		default:
			out.Info("Generating Curve25519 keypair...")
			pubKey, err = keys.GenerateDNSTTKeys(privKeyPath, pubKeyPath)
		}
		if err != nil {
			return actions.NewError(actions.TunnelAdd, "key setup failed", err)
		}

		recordType := ctx.GetArg("record-type")
		if recordType == "" {
			rtOpts := make([]actions.SelectOption, len(config.ValidVayDNSRecordTypes))
			for i, rt := range config.ValidVayDNSRecordTypes {
				rtOpts[i] = actions.SelectOption{Value: rt, Label: rt}
			}
			var err error
			recordType, err = prompt.Select("DNS record type", rtOpts)
			if err != nil {
				return err
			}
		}

		tunnel.VayDNS = &config.VayDNSConfig{
			MTU:        config.DefaultMTU,
			PrivateKey: privKeyPath,
			PublicKey:  pubKey,
			RecordType: recordType,
		}
		out.Success(fmt.Sprintf("Public key: %s", pubKey))

	case config.TransportNaive:
		email := ctx.GetArg("email")
		if email == "" {
			var err error
			email, err = prompt.String("Email (for Let's Encrypt)", "")
			if err != nil {
				return err
			}
		}
		decoyURL := ctx.GetArg("decoy-url")
		if decoyURL == "" {
			var err error
			decoyURL, err = prompt.String("Decoy URL", config.RandomDecoyURL())
			if err != nil {
				return err
			}
		}
		tunnel.Naive = &config.NaiveConfig{
			Email:    email,
			DecoyURL: decoyURL,
			Port:     443,
		}

	}

	// Add to config and save
	cfg.AddTunnel(tunnel)
	if cfg.Route.Active == "" {
		cfg.Route.Active = tag
		cfg.Route.Default = tag
	}

	// Auto-switch to multi mode when adding a second DNS tunnel
	if tunnel.IsDNSTunnel() && cfg.Route.Mode == "single" {
		dnsTunnelCount := 0
		for _, t := range cfg.Tunnels {
			if t.IsDNSTunnel() && t.Enabled {
				dnsTunnelCount++
			}
		}
		if dnsTunnelCount > 1 {
			cfg.Route.Mode = "multi"
			out.Info("Switched to multi-tunnel mode")
		}
	}

	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.TunnelAdd, "failed to save config", err)
	}

	// Free the port in case a stale process is holding it
	if tunnel.IsDNSTunnel() && tunnel.Port > 0 {
		network.FreePort(tunnel.Port, "udp")
	}

	// Create and start systemd service
	out.Info("Creating systemd service...")
	if err := transport.CreateService(&tunnel, cfg); err != nil {
		return actions.NewError(actions.TunnelAdd, "failed to create service", err)
	}

	if err := router.AddTunnel(cfg, &tunnel); err != nil {
		out.Warning("Failed to register with router: " + err.Error())
	}

	out.Success(fmt.Sprintf("Tunnel %q created and started", tag))
	out.Info(fmt.Sprintf("Share with: slipgate tunnel share %s", tag))
	return nil
}
