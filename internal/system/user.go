package system

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"

	"github.com/anonvector/slipgate/internal/config"
)

// EnsureUser creates the slipgate system user and groups if they don't exist.
func EnsureUser() error {
	// Create group
	if !groupExists(config.SystemGroup) {
		if err := run("groupadd", "--system", config.SystemGroup); err != nil {
			return fmt.Errorf("create group %s: %w", config.SystemGroup, err)
		}
	}

	// Create SSH group
	if !groupExists(config.SSHGroup) {
		if err := run("groupadd", "--system", config.SSHGroup); err != nil {
			return fmt.Errorf("create group %s: %w", config.SSHGroup, err)
		}
	}

	// Create user
	if !userExists(config.SystemUser) {
		if err := run("useradd", "--system", "--no-create-home",
			"--shell", "/usr/sbin/nologin",
			"--gid", config.SystemGroup,
			config.SystemUser); err != nil {
			return fmt.Errorf("create user %s: %w", config.SystemUser, err)
		}
	}

	return nil
}

// RemoveUser removes the slipgate system user and groups.
func RemoveUser() error {
	_ = run("userdel", config.SystemUser)
	_ = run("groupdel", config.SSHGroup)
	_ = run("groupdel", config.SystemGroup)
	return nil
}

// EnsureDir creates a directory owned by the slipgate user.
func EnsureDir(path, owner string) error {
	if err := os.MkdirAll(path, 0750); err != nil {
		return err
	}
	return run("chown", "-R", owner+":"+config.SystemGroup, path)
}

// AddSSHUser creates a system user in the slipgate-ssh group.
// If the user already exists, it updates the password instead.
func AddSSHUser(username, password string) error {
	// Ensure SSH group exists
	if !groupExists(config.SSHGroup) {
		if err := run("groupadd", "--system", config.SSHGroup); err != nil {
			return fmt.Errorf("create group %s: %w", config.SSHGroup, err)
		}
	}

	if !userExists(username) {
		if err := run("useradd", "--system", "--no-create-home",
			"--shell", "/bin/false",
			"--gid", config.SSHGroup,
			username); err != nil {
			return fmt.Errorf("create user: %w", err)
		}
	}

	// Set password
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("set password: %w", err)
	}

	// Ensure sshd Match Group config
	return ensureSSHMatchGroup()
}

// RemoveSSHUser removes a user from the system.
func RemoveSSHUser(username string) error {
	return run("userdel", username)
}

// ListSSHUsers returns all users in the slipgate-ssh group.
func ListSSHUsers() ([]string, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) >= 4 && parts[0] == config.SSHGroup {
			if parts[3] == "" {
				return nil, nil
			}
			return strings.Split(parts[3], ","), nil
		}
	}
	return nil, nil
}

// GeneratePassword generates a random alphanumeric password.
func GeneratePassword(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}
	return string(result)
}

func ensureSSHMatchGroup() error {
	const matchBlock = `
# SlipGate SSH tunnel users
Match Group slipgate-ssh
    AllowTcpForwarding yes
    X11Forwarding no
    AllowAgentForwarding no
    ForceCommand /bin/false
`
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return err
	}

	if strings.Contains(string(data), "Match Group slipgate-ssh") {
		return nil
	}

	f, err := os.OpenFile("/etc/ssh/sshd_config", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(matchBlock); err != nil {
		return err
	}

	// Try "sshd" (RHEL/CentOS) first, then "ssh" (Debian/Ubuntu)
	if err := run("systemctl", "reload", "sshd"); err != nil {
		return run("systemctl", "reload", "ssh")
	}
	return nil
}

func userExists(name string) bool {
	err := exec.Command("id", name).Run()
	return err == nil
}

func groupExists(name string) bool {
	err := exec.Command("getent", "group", name).Run()
	return err == nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, strings.TrimSpace(string(output)))
	}
	return nil
}
