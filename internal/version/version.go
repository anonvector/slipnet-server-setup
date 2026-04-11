package version

import "fmt"

var (
	Version    = "1.6.2"
	Commit     = "unknown"
	ReleaseTag = "" // set via ldflags for dev builds (e.g. "dev-abc1234")
)

func String() string {
	tag := ""
	if ReleaseTag != "" {
		tag = "-dev"
	}
	if Commit == "unknown" {
		return fmt.Sprintf("slipgate v%s%s", Version, tag)
	}
	return fmt.Sprintf("slipgate v%s%s (%s)", Version, tag, Commit)
}

// IsDev returns true if this is a dev channel build.
func IsDev() bool {
	return ReleaseTag != ""
}
