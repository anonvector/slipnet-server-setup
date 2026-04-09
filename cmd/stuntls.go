package cmd

import (
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/spf13/cobra"
)

func init() {
	stuntlsCmd := &cobra.Command{
		Use:   "stuntls",
		Short: "Built-in TLS + WebSocket SSH proxy",
	}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the TLS/WebSocket SSH proxy (used by systemd)",
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, _ := cmd.Flags().GetString("addr")
			port, _ := cmd.Flags().GetInt("port")
			sshAddr, _ := cmd.Flags().GetString("ssh")
			cert, _ := cmd.Flags().GetString("cert")
			key, _ := cmd.Flags().GetString("key")
			return proxy.ServeStunTLS(addr, port, sshAddr, cert, key)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	serveCmd.Flags().String("addr", "0.0.0.0", "Listen address")
	serveCmd.Flags().Int("port", 443, "Listen port")
	serveCmd.Flags().String("ssh", "127.0.0.1:22", "SSH backend address")
	serveCmd.Flags().String("cert", "", "TLS certificate file")
	serveCmd.Flags().String("key", "", "TLS private key file")

	stuntlsCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(stuntlsCmd)
}
