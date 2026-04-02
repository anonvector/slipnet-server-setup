package clientcfg

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/anonvector/slipgate/internal/config"
)

// URIOptions controls URI generation.
type URIOptions struct {
	ClientMode string // "dnstt" or "noizdns" (DNSTT transport only)
	Username   string // override SOCKS/SSH username
	Password   string // override SOCKS/SSH password
}

// b64 encodes a string as base64 (matching Android's Base64.NO_WRAP).
func b64(s string) string {
	if s == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// GenerateURI builds a slipnet:// URI from tunnel + backend config.
func GenerateURI(tunnel *config.TunnelConfig, backend *config.BackendConfig, cfg *config.Config, opts URIOptions) (string, error) {
	var fields [TotalFields]string

	// Version and type
	fields[FVersion] = "18"
	fields[FTunnelType] = GetTunnelType(tunnel.Transport, tunnel.Backend, opts.ClientMode)

	name := tunnel.Tag
	if opts.ClientMode == ClientModeNoizDNS {
		name = strings.ReplaceAll(name, "dnstt", "noizdns")
	}
	fields[FName] = name
	fields[FDomain] = tunnel.Domain

	// Defaults
	fields[FResolvers] = "8.8.8.8:53:0"
	fields[FAuthMode] = "0"
	fields[FKeepAlive] = "5000"
	fields[FCongestionControl] = "bbr"
	fields[FTCPListenPort] = "1080"
	fields[FTCPListenHost] = "127.0.0.1"
	fields[FGSOEnabled] = "0"
	fields[FSSHEnabled] = "0"
	fields[FSSHPort] = "22"
	fields[FFwdDNSThroughSSH] = "0"
	fields[FSSHHost] = getServerIP()
	fields[FUseServerDNS] = "0"
	fields[FDNSTransport] = "udp"
	fields[FSSHAuthType] = "password"
	fields[FSSHPrivateKey] = b64("")
	fields[FSSHKeyPassphrase] = b64("")
	fields[FTorBridgeLines] = b64("")
	fields[FDNSTTAuthoritative] = "0"
	fields[FNaivePort] = "443"
	fields[FNaivePass] = b64("")
	fields[FIsLocked] = "0"
	fields[FExpirationDate] = "0"
	fields[FAllowSharing] = "0"
	fields[FResolversHidden] = "0"
	fields[FNoizDNSStealth] = "0"
	fields[FDNSPayloadSize] = "0"
	fields[FSOCKS5ServerPort] = "1080"

	// Transport-specific
	switch tunnel.Transport {
	case config.TransportDNSTT:
		if tunnel.DNSTT != nil {
			fields[FPublicKey] = tunnel.DNSTT.PublicKey
		}

	case config.TransportVayDNS:
		if tunnel.VayDNS != nil {
			fields[FPublicKey] = tunnel.VayDNS.PublicKey
		}

	case config.TransportSlipstream:
		// No pubkey field needed

	case config.TransportNaive:
		if tunnel.Naive != nil {
			fields[FNaivePort] = fmt.Sprintf("%d", tunnel.Naive.Port)
			fields[FNaiveUser] = tunnel.Naive.User
			fields[FNaivePass] = b64(tunnel.Naive.Password)
			// Match server-side defaults from buildCaddyfile()
			if fields[FNaiveUser] == "" {
				fields[FNaiveUser] = "slipgate"
			}
			if tunnel.Naive.Password == "" {
				fields[FNaivePass] = b64("slipgate")
			}
		}

	case config.TransportSSH, config.TransportSOCKS:
		// Direct transports have no domain — use server IP
		fields[FDomain] = getServerIP()
	}

	// User credentials — always populate both SOCKS and SSH fields
	// The user/password is shared across SOCKS and SSH in slipgate
	username := opts.Username
	password := opts.Password

	if username == "" && backend != nil && backend.Type == config.BackendSOCKS && backend.SOCKS != nil {
		username = backend.SOCKS.User
		password = backend.SOCKS.Password
	}

	// SOCKS credentials (fields 12-13) — always set when we have a user
	fields[FSOCKSUser] = username
	fields[FSOCKSPass] = password

	// SSH fields (14-17, 19) — set for SSH tunnel types
	if tunnel.Backend == config.BackendSSH {
		fields[FSSHEnabled] = "1"
		fields[FSSHUser] = username
		fields[FSSHPass] = password
		fields[FSSHPort] = "22"
		fields[FSSHHost] = getServerIP()
	}

	// NaiveProxy requires naiveUsername/naivePassword (fields 29/30)
	if tunnel.Transport == config.TransportNaive && username != "" {
		fields[FNaiveUser] = username
		fields[FNaivePass] = b64(password)
	}

	return Encode(fields), nil
}

func getServerIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
