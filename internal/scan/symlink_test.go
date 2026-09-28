package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// Discovery lists regular files only: a symlink named .env in a scanned
// project, or a *.jsonl link in a transcript directory, could lead anywhere,
// and --scrub rewrites what transcript discovery returns.
func TestDiscoverSkipsSymlinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(outside, []byte("token=passess-fake-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(repo, ".env")); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	proj := filepath.Join(home, ".claude", "projects", "p")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(proj, "linked.jsonl")); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(proj, "real.jsonl")
	if err := os.WriteFile(real, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tg := range Discover(Where{Home: home, Dir: repo, Transcripts: true}) {
		if filepath.Base(tg.Path) == ".env" && filepath.Dir(tg.Path) == repo {
			t.Fatalf("the .env symlink was listed: %+v", tg)
		}
		if filepath.Base(tg.Path) == "linked.jsonl" {
			t.Fatalf("the transcript symlink was listed: %+v", tg)
		}
	}
	found := false
	for _, tg := range Discover(Where{Home: home, Transcripts: true}) {
		found = found || tg.Path == real
	}
	if !found {
		t.Fatal("the real transcript is no longer listed")
	}
}
