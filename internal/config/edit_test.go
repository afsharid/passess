package config

import (
	"strings"
	"testing"
)

const editBase = `version = 1

# the GitHub token
[secrets.GITHUB_TOKEN]
ref   = "keychain://passess/github" # kept in the keychain
allow = ["gh", "git"]

[secrets.DB_URL]
ref = [
  "env://DATABASE_URL",
  "keychain://passess/db",
]
clients = [
  "codex",
]

[profiles.web]
secrets = ["DB_URL"]
allow   = ["node"]
`

func lit(s string) *string { return &s }

func TestSetSecretFieldsInsertsWithinTheTable(t *testing.T) {
	got, err := SetSecretFields([]byte(editBase), "GITHUB_TOKEN", []Field{{"clients", lit(`["claude-code", "codex"]`)}, {"approve", lit("true")}})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(editBase, `allow = ["gh", "git"]
`, `allow = ["gh", "git"]
clients = ["claude-code", "codex"]
approve = true
`, 1)
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	u, err := ParseUser("config.toml", got)
	if err != nil {
		t.Fatal(err)
	}
	if s := u.Secrets["GITHUB_TOKEN"]; !s.Approve || strings.Join(s.Clients, ",") != "claude-code,codex" {
		t.Fatalf("parsed %+v", s)
	}
}

func TestSetSecretFieldsReplacesAndRemoves(t *testing.T) {
	// A multi-line value is replaced whole; a nil value removes the key.
	got, err := SetSecretFields([]byte(editBase), "DB_URL", []Field{{"clients", lit(`["opencode"]`)}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "clients = [\"opencode\"]\n\n[profiles.web]") || strings.Contains(string(got), `"codex"`) {
		t.Fatalf("replace:\n%s", got)
	}
	got, err = SetSecretFields(got, "DB_URL", []Field{{"clients", nil}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "clients") {
		t.Fatalf("remove:\n%s", got)
	}
	u, err := ParseUser("config.toml", got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Secrets["DB_URL"].Clients != nil {
		t.Fatal("clients should be gone: every agent")
	}
	// Removing a key that is not there changes nothing.
	again, err := SetSecretFields(got, "DB_URL", []Field{{"approve", nil}})
	if err != nil || string(again) != string(got) {
		t.Fatalf("no-op removal: %v\n%s", err, again)
	}
}

func TestSetSecretFieldsLastTableWithoutNewline(t *testing.T) {
	in := "version = 1\n[secrets.A]\nref = \"env://A\""
	got, err := SetSecretFields([]byte(in), "A", []Field{{"clients", lit("[]")}})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "version = 1\n[secrets.A]\nref = \"env://A\"\nclients = []\n" {
		t.Fatalf("got %q", got)
	}
	u, err := ParseUser("config.toml", got)
	if err != nil || u.Secrets["A"].Clients == nil || len(u.Secrets["A"].Clients) != 0 {
		t.Fatalf("an empty list means no agent: %v %+v", err, u)
	}
}

func TestSetSecretFieldsQuotedHeader(t *testing.T) {
	in := "version = 1\n[ secrets . \"A\" ] # quoted\nref = \"env://A\"\n"
	if _, err := SetSecretFields([]byte(in), "A", []Field{{"approve", lit("true")}}); err != nil {
		t.Fatal(err)
	}
}

func TestSetSecretFieldsRefusesWhatItCannotEditSafely(t *testing.T) {
	for name, in := range map[string]string{
		"inline table":      "version = 1\n[secrets]\nA = { ref = \"env://A\" }\n",
		"missing":           "version = 1\n[secrets.B]\nref = \"env://B\"\n",
		"multi-line string": "version = 1\n[secrets.A]\nref = \"env://A\"\nnote = \"\"\"\nline\n\"\"\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := SetSecretFields([]byte(in), "A", []Field{{"note", lit(`"x"`)}}); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
	// A value that is not TOML never reaches the file.
	if _, err := SetSecretFields([]byte(editBase), "DB_URL", []Field{{"clients", lit(`["a"`)}}); err == nil {
		t.Fatal("expected a refusal for a broken value")
	}
}

func TestRemoveSecret(t *testing.T) {
	got, err := RemoveSecret([]byte(editBase), "GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	// The comment right above the table goes with it; one blank line still
	// parts what was before it from what was after.
	want := strings.Replace(editBase, "# the GitHub token\n[secrets.GITHUB_TOKEN]\nref   = \"keychain://passess/github\" # kept in the keychain\nallow = [\"gh\", \"git\"]\n\n", "", 1)
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	got, err = RemoveSecret([]byte("version = 1\n\n[secrets.A]\nref = \"env://A\"\n"), "A")
	if err != nil || string(got) != "version = 1\n" {
		t.Fatalf("last table: %v %q", err, got)
	}
	if _, err := RemoveSecret([]byte(editBase), "NOPE"); err == nil {
		t.Fatal("removing a missing table should fail")
	}
}
