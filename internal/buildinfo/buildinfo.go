// Package buildinfo reports the version of the running binary.
package buildinfo

import "runtime/debug"

// Version is set at link time with
// -ldflags "-X github.com/afsharid/passess/internal/buildinfo.Version=v0.1.0".
var Version = ""

// String returns the release version when one was linked in, otherwise the
// module version or VCS revision recorded by the Go toolchain.
func String() string {
	if Version != "" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev == "" {
		return "dev"
	}
	return "dev-" + rev + dirty
}
