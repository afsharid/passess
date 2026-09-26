package harness

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Backup copies the files that exist among paths into a new timestamped
// directory under root, with a manifest mapping each copy to its original. It
// returns the directory. Copies are 0600 in a 0700 directory: harness configs
// can hold credentials in clear.
func Backup(root string, paths []string, now time.Time) (string, error) {
	dir := filepath.Join(root, now.Format("20060102-150405.000"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	type item struct {
		Original string `json:"original"`
		Copy     string `json:"copy"`
	}
	var manifest []item
	for i, p := range paths {
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		// The name is flattened: every "/" becomes "_", so it cannot leave dir.
		name := fmt.Sprintf("%02d-%s", i, strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "_"))
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil { //nolint:gosec // G703: see above

			return "", err
		}
		manifest = append(manifest, item{Original: p, Copy: name})
	}
	m, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	return dir, os.WriteFile(filepath.Join(dir, "manifest.json"), m, 0o600)
}
