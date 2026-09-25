package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadUser(t *testing.T) {
	p := write(t, "config.toml", `
version = 1
[backends.bws]
access_token = "keychain://passess/bws"

[secrets.GITHUB_TOKEN]
ref   = "op://Dev/GitHub PAT/credential"
allow = ["gh", "git"]

[secrets.NVIDIA_API_KEY]
ref = ["bws://dev-project/NVIDIA_API_KEY", "bws://dev-project/NGC_API_KEY"]

[profiles.gateway]
secrets  = ["NVIDIA_API_KEY"]
required = ["NVIDIA_API_KEY"]
allow    = ["gatewayd"]
`)
	u, err := LoadUser(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Secrets["GITHUB_TOKEN"]; len(got.Refs) != 1 || got.Refs[0].Scheme != "op" || len(got.Allow) != 2 {
		t.Fatalf("GITHUB_TOKEN = %+v", got)
	}
	if got := u.Secrets["NVIDIA_API_KEY"].Refs; len(got) != 2 || got[1].Path[1] != "NGC_API_KEY" {
		t.Fatalf("candidates = %+v", got)
	}
	if u.Backends.BWS.AccessToken == nil || u.Backends.BWS.AccessToken.Scheme != "keychain" {
		t.Fatalf("bws token ref = %+v", u.Backends.BWS.AccessToken)
	}
	if p := u.Profiles["gateway"]; len(p.Secrets) != 1 || p.Allow[0] != "gatewayd" {
		t.Fatalf("profile = %+v", p)
	}
}

func TestLoadUserErrorsDoNotEchoSource(t *testing.T) {
	pasted := "passess-fake-pasted-value-0123456789"
	for name, body := range map[string]string{
		"value instead of ref":  "version = 1\n[secrets.A]\nref = \"" + pasted + "\"\n",
		"unknown key":           "version = 1\n[secrets.A]\nref = \"env://A\"\nvalue = \"" + pasted + "\"\n",
		"broken toml":           "version = 1\n[secrets.A]\nref = \"env://A\n" + pasted + "\n",
		"missing version":       "[secrets.A]\nref = \"env://A\"\n",
		"bad name":              "version = 1\n[secrets.\"not-a-name\"]\nref = \"env://A\"\n",
		"path in allow":         "version = 1\n[secrets.A]\nref = \"env://A\"\nallow = [\"/bin/sh\"]\n",
		"profile without allow": "version = 1\n[secrets.A]\nref = \"env://A\"\n[profiles.p]\nsecrets = [\"A\"]\n",
		"profile unknown name":  "version = 1\n[profiles.p]\nsecrets = [\"B\"]\nallow = [\"x\"]\n",
		"bws token in bws":      "version = 1\n[backends.bws]\naccess_token = \"bws://p/TOKEN\"\n",
	} {
		_, err := LoadUser(write(t, "config.toml", body))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), pasted) {
			t.Errorf("%s: error echoes the file: %v", name, err)
		}
	}
}

func TestLoadProject(t *testing.T) {
	p := write(t, ProjectFile, "version = 1\n[needs.DATABASE_URL]\nnote = \"dev db\"\n[needs.STRIPE_KEY]\nallow = [\"stripe\"]\n")
	proj, err := LoadProject(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(proj.Needs) != 2 || proj.ProjectAllow("STRIPE_KEY")[0] != "stripe" || proj.ProjectAllow("DATABASE_URL") != nil {
		t.Fatalf("needs = %+v", proj.Needs)
	}
	var none *Project
	if none.ProjectAllow("X") != nil {
		t.Fatal("nil project must allow no narrowing")
	}

	for name, body := range map[string]string{
		"ref in needs":    "version = 1\n[needs.A]\nref = \"keychain://x/y\"\n",
		"secrets section": "version = 1\n[secrets.A]\nref = \"keychain://x/y\"\n",
	} {
		if _, err := LoadProject(write(t, ProjectFile, body)); err == nil || !strings.Contains(err.Error(), "user config") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestFindProjectWalksUp(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "a", ProjectFile)
	if err := os.WriteFile(want, []byte("version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := FindProject(deep); got != want {
		t.Fatalf("FindProject = %q, want %q", got, want)
	}
}

func TestUserPath(t *testing.T) {
	env := map[string]string{"HOME": "/h"}
	get := func(k string) string { return env[k] }
	if p, _ := UserPath(get); p != "/h/.config/passess/config.toml" {
		t.Fatal(p)
	}
	env["XDG_CONFIG_HOME"] = "/x"
	if p, _ := UserPath(get); p != "/x/passess/config.toml" {
		t.Fatal(p)
	}
	env["PASSESS_CONFIG"] = "/c.toml"
	if p, _ := UserPath(get); p != "/c.toml" {
		t.Fatal(p)
	}
}
