package cmd

import (
	"strings"

	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/spf13/cobra"
)

func init() {
	socksCmd := &cobra.Command{
		Use:   "socks",
		Short: "Built-in SOCKS5 proxy",
	}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the SOCKS5 proxy (used by systemd)",
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, _ := cmd.Flags().GetString("addr")
			port, _ := cmd.Flags().GetInt("port")
			credsList, _ := cmd.Flags().GetStringArray("creds")

			// Parse --creds user:pass pairs
			creds := make(map[string]string)
			for _, c := range credsList {
				if i := strings.IndexByte(c, ':'); i > 0 {
					creds[c[:i]] = c[i+1:]
				}
			}

			// Fall back to legacy --user/--pass for single-user compat
			if len(creds) == 0 {
				user, _ := cmd.Flags().GetString("user")
				pass, _ := cmd.Flags().GetString("pass")
				if user != "" {
					creds[user] = pass
				}
			}

			return proxy.ServeMulti(addr, port, creds)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	serveCmd.Flags().String("addr", "127.0.0.1", "Listen address")
	serveCmd.Flags().Int("port", 1080, "Listen port")
	serveCmd.Flags().String("user", "", "Username for auth (single user, legacy)")
	serveCmd.Flags().String("pass", "", "Password for auth (single user, legacy)")
	serveCmd.Flags().StringArray("creds", nil, "Credentials as user:pass (repeatable)")

	socksCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(socksCmd)
}
