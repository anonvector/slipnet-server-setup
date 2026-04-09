package version

import "fmt"

var (
	Version    = "1.6.0"
	Commit     = "unknown"
	ReleaseTag = "" // set via ldflags for dev builds (e.g. "dev-abc1234")
)

func String() string {
	if Commit == "unknown" {
		return fmt.Sprintf("slipgate v%s", Version)
	}
	return fmt.Sprintf("slipgate v%s (%s)", Version, Commit)
}
