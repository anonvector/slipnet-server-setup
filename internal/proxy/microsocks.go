package proxy

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
)

const (
	socksServiceName = "slipgate-socks5"
	// socksCredsFile holds `user:pass` lines, one per user. The `socks serve`
	// command reads this at start and on SIGHUP, so credential changes do not
	// require a process restart (which would drop every active client).
	socksCredsFile = config.DefaultConfigDir + "/socks-users.conf"
)

// RunAsUser overrides the system user for the SOCKS5 service.
// When non-empty the service runs as this user instead of config.SystemUser.
// Set this before calling any Setup* function when WARP routing is active.
var RunAsUser string

// SetupSOCKS creates the SOCKS5 proxy service (localhost only, no auth).
func SetupSOCKS() error {
	return setupSOCKSMulti("127.0.0.1", nil)
}

// SetupSOCKSWithAuth creates the SOCKS5 proxy with a single user (localhost only).
func SetupSOCKSWithAuth(user, password string) error {
	return setupSOCKSMulti("127.0.0.1", []config.UserConfig{{Username: user, Password: password}})
}

// SetupSOCKSWithUsers creates the SOCKS5 proxy with multiple users (localhost only).
func SetupSOCKSWithUsers(users []config.UserConfig) error {
	return setupSOCKSMulti("127.0.0.1", users)
}

// SetupSOCKSExternal creates the SOCKS5 proxy on all interfaces (for direct SOCKS5).
func SetupSOCKSExternal(user, password string) error {
	return setupSOCKSMulti("0.0.0.0", []config.UserConfig{{Username: user, Password: password}})
}

// SetupSOCKSExternalWithUsers creates the SOCKS5 proxy on all interfaces with multiple users.
func SetupSOCKSExternalWithUsers(users []config.UserConfig) error {
	return setupSOCKSMulti("0.0.0.0", users)
}

func setupSOCKSMulti(listenAddr string, users []config.UserConfig) error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	if err := writeSocksCredsFile(users); err != nil {
		return fmt.Errorf("write creds file: %w", err)
	}

	args := fmt.Sprintf("%s socks serve --addr %s --port 1080 --creds-file %s", execPath, listenAddr, socksCredsFile)

	// Clean up old microsocks service if it exists
	_ = service.Stop("slipgate-microsocks")
	_ = service.Remove("slipgate-microsocks")

	svcUser := config.SystemUser
	if RunAsUser != "" {
		svcUser = RunAsUser
	}

	unit := &service.Unit{
		Name:        socksServiceName,
		Description: "SlipGate SOCKS5 proxy",
		ExecStart:   args,
		ExecReload:  "/bin/kill -HUP $MAINPID",
		User:        svcUser,
		Group:       config.SystemGroup,
		After:       "network.target",
		Restart:     "always",
	}

	// If the installed unit file already matches the desired ExecStart and
	// User, the only thing that changed is the creds file contents. Hot-reload
	// via SIGHUP so existing client connections survive.
	if existing := service.ReadUnitFile(socksServiceName); existing != "" &&
		strings.Contains(existing, "ExecStart="+args+"\n") &&
		strings.Contains(existing, "User="+svcUser+"\n") {
		if err := service.Reload(socksServiceName); err == nil {
			return nil
		}
		// Fall through to recreate+restart if reload fails (e.g. service not running yet).
	}

	if err := service.Create(unit); err != nil {
		return err
	}

	// New or changed unit: pick up the new ExecStart with a restart.
	_ = service.Restart(unit.Name)
	return service.Start(unit.Name)
}

// writeSocksCredsFile writes the current credential set to socksCredsFile
// atomically (temp file + rename) so a concurrent SIGHUP reader never sees
// a partial file.
func writeSocksCredsFile(users []config.UserConfig) error {
	if err := os.MkdirAll(filepath.Dir(socksCredsFile), 0750); err != nil {
		return err
	}

	var buf strings.Builder
	for _, u := range users {
		if u.Username != "" && u.Password != "" {
			fmt.Fprintf(&buf, "%s:%s\n", u.Username, u.Password)
		}
	}

	tmp := socksCredsFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(buf.String()), 0640); err != nil {
		return err
	}
	// The SOCKS service runs as either SystemUser or SocksUser, both of
	// which have SystemGroup as their primary group; chown so either can
	// read the file without making it world-readable. Only root can change
	// ownership — warn loudly when we can't, so the broken auth (SOCKS
	// service unable to read the file it was handed) is diagnosable.
	if os.Geteuid() == 0 {
		if err := exec.Command("chown", config.SystemUser+":"+config.SystemGroup, tmp).Run(); err != nil {
			log.Printf("warning: chown %s failed: %v (SOCKS service may not be able to read creds)", tmp, err)
		}
	} else {
		log.Printf("warning: not running as root, skipping chown of %s (SOCKS service may not be able to read creds)", socksCredsFile)
	}
	return os.Rename(tmp, socksCredsFile)
}
