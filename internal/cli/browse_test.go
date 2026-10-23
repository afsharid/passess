package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/provider"
)

// browseValue is in every value op sends; no output may hold it.
const browseValue = "passess-fake-op-value-0123456789"

// opFake answers op as the 1Password CLI would, values and all.
type opFake struct{ t *testing.T }

func (f opFake) Run(_ context.Context, c provider.Cmd) (provider.Result, error) {
	if c.Name != "op" || !slices.Contains(c.Args, "--format") {
		f.t.Fatalf("unexpected command %s %v", c.Name, c.Args)
	}
	switch strings.Join(c.Args[:2], " ") {
	case "vault list":
		return provider.Result{Stdout: []byte(`[{"id":"v1abc","name":"Private","content_version":12},{"id":"v2def","name":"Work"}]`)}, nil
	case "item list":
		return provider.Result{Stdout: []byte(`[{"id":"i1abc","title":"GitHub","category":"API_CREDENTIAL","vault":{"id":"v1abc","name":"Private"}},
			{"id":"i2def","title":"OpenRouter","category":"LOGIN","vault":{"id":"v1abc","name":"Private"}}]`)}, nil
	case "item get":
		return provider.Result{Stdout: []byte(`{"id":"i1abc","title":"GitHub","category":"API_CREDENTIAL",
			"vault":{"id":"v1abc","name":"Private"},
			"sections":[{"id":"s1","label":"Tokens"}],
			"fields":[
			  {"id":"credential","type":"CONCEALED","label":"credential","value":"` + browseValue + `","reference":"op://Private/GitHub/credential"},
			  {"id":"f2","type":"CONCEALED","label":"read token","section":{"id":"s1","label":"Tokens"},"value":"` + browseValue + `-2","reference":"op://Private/GitHub/Tokens/read token"},
			  {"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain","value":"` + browseValue + `-3","reference":"op://Private/GitHub/notesPlain"},
			  {"id":"totp","type":"OTP","label":"one-time password","value":"` + browseValue + `-4","totp":"123456","reference":"op://Private/GitHub/one-time password?attribute=otp"}
			]}`)}, nil
	}
	f.t.Fatalf("unexpected op %v", c.Args)
	return provider.Result{}, nil
}

// dumpFake answers security dump-keychain, refusing -d (values).
type dumpFake struct{ t *testing.T }

const keychainDump = `keychain: "/Users/you/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="passess GITHUB_TOKEN"
    "acct"<blob>="GITHUB_TOKEN"
    "mdat"<timedate>=0x32303236313031393139333934385A00  "20261019193948Z\000"
    "svce"<blob>="passess"
keychain: "/Users/you/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="someone-else"
    "svce"<blob>="other"
keychain: "/Users/you/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="bws"
    "mdat"<timedate>=0x32303236303932363134353435365A00  "20260926145456Z\000"
    "svce"<blob>="passess"
keychain: "/Users/you/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>=0x00FF
    "svce"<blob>="passess"
keychain: "/Users/you/Library/Keychains/login.keychain-db"
version: 512
class: "inet"
attributes:
    "acct"<blob>="INET_ONLY"
    "svce"<blob>="passess"
`

func (f dumpFake) Run(_ context.Context, c provider.Cmd) (provider.Result, error) {
	if c.Name != "security" || len(c.Args) != 1 || c.Args[0] != "dump-keychain" {
		f.t.Fatalf("browse keychain may only run security dump-keychain, without -d: %s %v", c.Name, c.Args)
	}
	return provider.Result{Stdout: []byte(keychainDump)}, nil
}

func fakeBrowse(t *testing.T, r provider.Runner) {
	t.Helper()
	saved, goos := browseRunner, browseGOOS
	t.Cleanup(func() { browseRunner, browseGOOS = saved, goos })
	browseRunner, browseGOOS = r, "darwin"
}

// hasKey reports whether any object in the JSON document has key.
func hasKey(v any, key string) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if k == key || hasKey(e, key) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if hasKey(e, key) {
				return true
			}
		}
	}
	return false
}

func TestBrowseOPNeverPrintsAValue(t *testing.T) {
	noHarness(t)
	writeConfig(t, `version = 1
[secrets.GITHUB_TOKEN]
ref = "op://Private/GitHub/credential"
`)
	fakeBrowse(t, opFake{t})
	for _, args := range [][]string{
		{"browse", "op", "--json"},
		{"browse", "op", "--vault", "Private", "--json"},
		{"browse", "op", "--vault", "Private", "--item", "GitHub", "--json"},
		{"browse", "op", "--vault", "Private", "--item", "GitHub"},
	} {
		out, errOut, code := run(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d, %q", args, code, errOut)
		}
		if strings.Contains(out+errOut, browseValue) || strings.Contains(out, "123456") {
			t.Fatalf("%v printed a value:\n%s", args, out)
		}
		if args[len(args)-1] != "--json" {
			continue
		}
		var doc any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		for _, k := range []string{"value", "totp"} {
			if hasKey(doc, k) {
				t.Fatalf("%v: the output has a %q key:\n%s", args, k, out)
			}
		}
	}

	out, _, _ := run(t, "browse", "op", "--vault", "Private", "--item", "GitHub", "--json")
	var got opBrowseOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Fields) != 4 || got.Fields[0].UsedBy != "GITHUB_TOKEN" || got.Fields[1].Ref != "op://Private/GitHub/Tokens/read token" ||
		got.Fields[1].Section != "Tokens" || got.Fields[3].Type != "OTP" {
		t.Fatalf("fields: %+v", got.Fields)
	}
}

func TestBrowseUsage(t *testing.T) {
	noHarness(t)
	writeConfig(t, "version = 1\n")
	fakeBrowse(t, opFake{t})
	for _, args := range [][]string{{"browse"}, {"browse", "bw"}, {"browse", "op", "--item", "GitHub"}, {"browse", "keychain", "--vault", "x"}} {
		if _, _, code := run(t, args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
}

func TestBrowseRefusedUnderAgent(t *testing.T) {
	noHarness(t)
	writeConfig(t, "version = 1\n")
	fakeBrowse(t, opFake{t})
	t.Setenv("CLAUDECODE", "1")
	if _, errOut, code := run(t, "browse", "op", "--json"); code != ExitNoPerm {
		t.Fatalf("under an agent: exit %d, %q", code, errOut)
	}
}

func TestBrowseKeychain(t *testing.T) {
	noHarness(t)
	writeConfig(t, `version = 1
[secrets.GITHUB_TOKEN]
ref = "keychain://passess/GITHUB_TOKEN"
`)
	fakeBrowse(t, dumpFake{t})
	out, errOut, code := run(t, "browse", "keychain", "--json")
	if code != 0 {
		t.Fatalf("exit %d, %q", code, errOut)
	}
	var got keychainBrowseOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	want := []keychainEntry{
		{Account: "GITHUB_TOKEN", Ref: "keychain://passess/GITHUB_TOKEN", Modified: "2026-10-19T19:39:48Z", UsedBy: "GITHUB_TOKEN"},
		{Account: "bws", Ref: "keychain://passess/bws", Modified: "2026-09-26T14:54:56Z", Backend: "bws"},
	}
	if !slices.Equal(got.Items, want) {
		t.Fatalf("items:\n got %+v\nwant %+v", got.Items, want)
	}

	// The bws machine token opens the vault: add and set refuse it.
	for _, args := range [][]string{{"add", "BWS", "--ref", "keychain://passess/bws"}, {"set", "GITHUB_TOKEN", "--ref", "keychain://passess/bws"}} {
		if _, errOut, code := run(t, args...); code == 0 || !strings.Contains(errOut, "credential bws itself reads") {
			t.Errorf("%v: exit %d, %q", args, code, errOut)
		}
	}

	browseGOOS = "linux"
	if _, _, code := run(t, "browse", "keychain", "--json"); code != ExitUnavailable {
		t.Fatalf("off macOS: exit %d", code)
	}
}

// TestMenuBarBrowseFixtures pins browse's JSON, which the app's Add tab reads.
func TestMenuBarBrowseFixtures(t *testing.T) {
	noHarness(t)
	dir := writeConfig(t, `version = 1
[secrets.GITHUB_TOKEN]
ref = "op://Private/GitHub/credential"
[secrets.GH_LOCAL]
ref = "keychain://passess/GITHUB_TOKEN"
`)
	fakeBrowse(t, opFake{t})
	out, _, _ := run(t, "browse", "op", "--json")
	golden(t, "browse-op-vaults.json", out, dir)
	out, _, _ = run(t, "browse", "op", "--vault", "Private", "--json")
	golden(t, "browse-op-items.json", out, dir)
	out, _, _ = run(t, "browse", "op", "--vault", "Private", "--item", "GitHub", "--json")
	golden(t, "browse-op-fields.json", out, dir)
	browseRunner = dumpFake{t}
	out, _, _ = run(t, "browse", "keychain", "--json")
	golden(t, "browse-keychain.json", out, dir)
}

// TestBeforeTheFirstSecret: Passess.app's setup lists the agents and browses
// 1Password before any config exists; add then starts the file.
func TestBeforeTheFirstSecret(t *testing.T) {
	noHarness(t)
	dir := t.TempDir()
	t.Setenv("PASSESS_CONFIG", filepath.Join(dir, "config.toml"))
	t.Chdir(dir)
	fakeBrowse(t, opFake{t})
	out, errOut, code := run(t, "list", "--json")
	var got listOutput
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || len(got.Secrets) != 0 || len(got.Agents) == 0 {
		t.Fatalf("list without a config: exit %d, %q\n%s", code, errOut, out)
	}
	if _, errOut, code := run(t, "browse", "op", "--json"); code != 0 {
		t.Fatalf("browse without a config: exit %d, %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("reading wrote a config: %v", err)
	}
}
