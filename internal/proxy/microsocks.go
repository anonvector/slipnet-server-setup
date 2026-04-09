package proxy

import (
	"fmt"
	"os"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
)

const socksServiceName = "slipgate-socks5"

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

	args := fmt.Sprintf("%s socks serve --addr %s --port 1080", execPath, listenAddr)
	for _, u := range users {
		if u.Username != "" && u.Password != "" {
			args += fmt.Sprintf(" --creds %s:%s", u.Username, u.Password)
		}
	}

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
		User:        svcUser,
		Group:       config.SystemGroup,
		After:       "network.target",
		Restart:     "always",
	}

	if err := service.Create(unit); err != nil {
		return err
	}

	// Restart to pick up new ExecStart (e.g. after adding auth)
	_ = service.Restart(unit.Name)
	return service.Start(unit.Name)
}
