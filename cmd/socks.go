package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

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
			credsFile, _ := cmd.Flags().GetString("creds-file")

			creds := parseCredsList(credsList)

			if credsFile != "" {
				fileCreds, err := readCredsFile(credsFile)
				if err != nil {
					return fmt.Errorf("read creds-file: %w", err)
				}
				for u, p := range fileCreds {
					creds[u] = p
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

			listenAddr := fmt.Sprintf("%s:%d", addr, port)
			srv := proxy.NewServerMulti(listenAddr, creds)

			// On SIGHUP, re-read the creds-file and swap credentials live,
			// leaving existing client connections untouched.
			if credsFile != "" {
				go watchCredsFile(srv, credsFile)
			}

			return srv.ListenAndServe()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	serveCmd.Flags().String("addr", "127.0.0.1", "Listen address")
	serveCmd.Flags().Int("port", 1080, "Listen port")
	serveCmd.Flags().String("user", "", "Username for auth (single user, legacy)")
	serveCmd.Flags().String("pass", "", "Password for auth (single user, legacy)")
	serveCmd.Flags().StringArray("creds", nil, "Credentials as user:pass (repeatable)")
	serveCmd.Flags().String("creds-file", "", "Path to a file with user:pass per line; SIGHUP reloads")

	socksCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(socksCmd)
}

func parseCredsList(list []string) map[string]string {
	creds := make(map[string]string)
	for _, c := range list {
		if i := strings.IndexByte(c, ':'); i > 0 {
			creds[c[:i]] = c[i+1:]
		}
	}
	return creds
}

// readCredsFile parses a file of `user:pass` lines (one per line). Blank lines
// and lines starting with '#' are ignored.
func readCredsFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	creds := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		creds[line[:i]] = line[i+1:]
	}
	return creds, scanner.Err()
}

func watchCredsFile(srv *proxy.Server, path string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	for range sig {
		creds, err := readCredsFile(path)
		if err != nil {
			log.Printf("reload creds-file %s: %v", path, err)
			continue
		}
		srv.SetCredentials(creds)
		log.Printf("SOCKS5 creds reloaded (%d users)", len(creds))
	}
}
