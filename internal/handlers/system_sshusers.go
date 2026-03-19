package handlers

import (
	"fmt"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/clientcfg"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/system"
)

func handleSystemUsers(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output
	action := ctx.GetArg("action")
	username := ctx.GetArg("username")

	if action == "" {
		var err error
		action, err = prompt.Select("Action", []actions.SelectOption{
			{Value: "add", Label: "Add user"},
			{Value: "remove", Label: "Remove user"},
			{Value: "list", Label: "List users & configs"},
		})
		if err != nil {
			return err
		}
	}

	switch action {
	case "list":
		if len(cfg.Users) == 0 {
			out.Info("No users configured. Run 'slipgate users add' to create one.")
			return nil
		}

		// Show user list
		out.Print("")
		for _, u := range cfg.Users {
			out.Print(fmt.Sprintf("  %s", u.Username))
		}
		out.Print("")

		// Let user pick one to see configs
		userOpts := make([]actions.SelectOption, 0, len(cfg.Users))
		for _, u := range cfg.Users {
			userOpts = append(userOpts, actions.SelectOption{Value: u.Username, Label: u.Username})
		}
		selectedUser, err := prompt.Select("Show configs for user", userOpts)
		if err != nil {
			return err
		}

		user := cfg.GetUser(selectedUser)
		if user == nil {
			return actions.NewError(actions.SystemUsers, "user not found", nil)
		}

		out.Print("")
		out.Print(fmt.Sprintf("  User: %s", user.Username))
		out.Print(fmt.Sprintf("  Password: %s", user.Password))
		out.Print("")

		if len(cfg.Tunnels) == 0 {
			out.Print("  No tunnels configured")
		} else {
			showUserConfigs(cfg, user.Username, user.Password, out)
		}

	case "add":
		if username == "" {
			var err error
			username, err = prompt.String("Username", "")
			if err != nil {
				return err
			}
		}
		if username == "" {
			return actions.NewError(actions.SystemUsers, "username is required", nil)
		}
		if cfg.GetUser(username) != nil {
			return actions.NewError(actions.SystemUsers, fmt.Sprintf("user %q already exists", username), nil)
		}

		password, err := prompt.String("Password (leave blank to generate)", "")
		if err != nil {
			return err
		}
		if password == "" {
			password = system.GeneratePassword(16)
			out.Info(fmt.Sprintf("Generated password: %s", password))
		}

		// Create SSH system user
		if err := system.AddSSHUser(username, password); err != nil {
			return actions.NewError(actions.SystemUsers, "failed to create SSH user", err)
		}

		// Update microsocks with auth
		if err := proxy.SetupMicrosocksWithAuth(username, password); err != nil {
			out.Warning("Failed to update SOCKS proxy auth: " + err.Error())
		}

		// Save to config
		cfg.AddUser(config.UserConfig{Username: username, Password: password})
		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemUsers, "failed to save config", err)
		}

		out.Success(fmt.Sprintf("User %q added (SSH + SOCKS)", username))

		// Show configs if tunnels exist
		if len(cfg.Tunnels) > 0 {
			out.Print("")
			out.Info("Configs for this user:")
			showUserConfigs(cfg, username, password, out)
		}

	case "remove":
		if username == "" {
			var err error
			username, err = prompt.String("Username", "")
			if err != nil {
				return err
			}
		}
		if username == "" {
			return actions.NewError(actions.SystemUsers, "username is required", nil)
		}

		if err := system.RemoveSSHUser(username); err != nil {
			out.Warning("Failed to remove SSH user: " + err.Error())
		}

		cfg.RemoveUser(username)

		if len(cfg.Users) > 0 {
			first := cfg.Users[0]
			_ = proxy.SetupMicrosocksWithAuth(first.Username, first.Password)
		} else {
			_ = proxy.SetupMicrosocks()
		}

		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemUsers, "failed to save config", err)
		}

		out.Success(fmt.Sprintf("User %q removed", username))
	}

	return nil
}

func showUserConfigs(cfg *config.Config, username, password string, out actions.OutputWriter) {
	for _, t := range cfg.Tunnels {
		backend := cfg.GetBackend(t.Backend)
		if backend == nil {
			continue
		}

		// Show public key for DNSTT tunnels
		if t.Transport == config.TransportDNSTT && t.DNSTT != nil && t.DNSTT.PublicKey != "" {
			out.Print(fmt.Sprintf("  [%s] Public Key: %s", t.Tag, t.DNSTT.PublicKey))
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
			uri, err := clientcfg.GenerateURI(&t, backend, cfg, opts)
			if err != nil {
				continue
			}
			label := t.Tag
			if mode == clientcfg.ClientModeNoizDNS {
				label = strings.ReplaceAll(label, "dnstt", "noizdns")
			}
			out.Print(fmt.Sprintf("  [%s]", label))
			out.Print(fmt.Sprintf("  %s", uri))
			out.Print("")
		}
	}
}
