package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/afsharid/passess/internal/buildinfo"
	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/scan"
)

func init() {
	commands["inventory"] = command{"write a Markdown inventory of your secrets: where each lives and what receives it, never a value", runInventory}
}

var backendLabel = map[string]string{
	ref.OnePassword: "1Password", ref.BWS: "Bitwarden Secrets Manager", ref.Bitwarden: "Bitwarden",
	ref.Vault: "Vault / OpenBao", ref.Keychain: "OS keychain", ref.Env: "environment",
}

func runInventory(st *Streams, args []string) int {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(st.Stderr, "Usage: passess inventory > SECRETS-INVENTORY.md")
		fmt.Fprintln(st.Stderr, "Built from your passess config and harness configs; nothing is resolved, no value is printed.")
	}
	if rest, err := parseAnywhere(fs, args); err != nil || len(rest) > 0 {
		fs.Usage()
		return ExitUsage
	}
	augmentPath(st.Getenv)
	u, proj, code := loadConfig(st)
	if code != ExitOK {
		return code
	}
	var harnesses []harnessReport
	for _, a := range adapters(st) {
		if a.Installed() {
			harnesses = append(harnesses, report(a, "status", desiredServers(u, a.ID()), false))
		}
	}
	fmt.Fprint(st.Stdout, inventory(u, proj, harnesses, st.Getenv("HOME"), time.Now()))
	return ExitOK
}

// cell makes s safe inside a Markdown table cell.
func cell(s string) string {
	if s == "" {
		return "—"
	}
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
}

func code(s string) string { return "`" + strings.ReplaceAll(s, "`", "'") + "`" }

func inventory(u *config.User, proj *config.Project, harnesses []harnessReport, home string, now time.Time) string {
	var b strings.Builder
	short := func(p string) string {
		if home != "" && strings.HasPrefix(p, home+"/") {
			return "~" + p[len(home):]
		}
		return p
	}
	row := func(cells ...string) {
		b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
	}
	fmt.Fprintf(&b, "# Secret inventory\n\nNo values: where each secret lives, what receives it and how to change it.\n")
	fmt.Fprintf(&b, "Written by passess %s on %s from %s.\n", buildinfo.String(), now.Format("2006-01-02"), code(short(u.Path)))

	// Who receives each secret, besides `passess exec` by an allowed program.
	consumers := map[string][]string{}
	for _, name := range sortedKeys(u.MCP) {
		for _, s := range u.MCP[name].Secrets() {
			consumers[s] = append(consumers[s], "mcp "+name)
		}
	}
	for _, name := range sortedKeys(u.Profiles) {
		for _, s := range u.Profiles[name].Secrets {
			consumers[s] = append(consumers[s], "profile "+name)
		}
	}
	if proj != nil {
		for n := range proj.Needs {
			consumers[n] = append(consumers[n], "this project")
		}
	}

	type keychainItem struct{ service, account, use string }
	var items []keychainItem
	noteKeychain := func(r ref.Ref, use string) {
		if r.Scheme == ref.Keychain && len(r.Path) == 2 {
			items = append(items, keychainItem{r.Path[0], r.Path[1], use})
		}
	}

	fmt.Fprintf(&b, "\n## Secrets\n\n")
	if len(u.Secrets) == 0 {
		b.WriteString("None configured yet: `passess add NAME --ref …`.\n")
	} else {
		row("Name", "Lives in", "Received by", "Programs", "Note")
		row("---", "---", "---", "---", "---")
		for _, name := range u.SortedNames() {
			s := u.Secrets[name]
			var where []string
			for i, r := range s.Refs {
				w := backendLabel[r.Scheme] + " " + code(r.String())
				if i > 0 {
					w = "else " + w
				}
				where = append(where, w)
				noteKeychain(r, name)
			}
			programs := "any but shells and interpreters"
			if len(s.Allow) > 0 {
				programs = strings.Join(s.Allow, ", ")
			}
			row(code(name), cell(strings.Join(where, ", ")), cell(strings.Join(consumers[name], ", ")), cell(programs), cell(s.Note))
		}
	}
	if proj != nil {
		var missing []string
		for n := range proj.Needs {
			if _, ok := u.Secrets[n]; !ok {
				missing = append(missing, n)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			fmt.Fprintf(&b, "\nThis project (%s) also needs: %s. Not configured yet.\n", code(short(proj.Path)), strings.Join(missing, ", "))
		}
	}

	if len(u.MCP) > 0 {
		fmt.Fprintf(&b, "\n## MCP servers\n\nHarnesses start each as `passess mcp-exec NAME`; the command and the credentials stay in the passess config.\n\n")
		header := []string{"Server", "Runs", "Credentials"}
		for _, h := range harnesses {
			header = append(header, h.Label)
		}
		row(header...)
		row(strings.Split(strings.Repeat("---,", len(header)), ",")[:len(header)]...)
		state := func(h harnessReport, name string) string {
			for _, s := range h.Servers {
				if s.Name == name {
					return s.State
				}
			}
			return "—"
		}
		for _, name := range sortedKeys(u.MCP) {
			m := u.MCP[name]
			runs := code(strings.Join(m.Command, " "))
			var creds []string
			if m.URL != "" {
				runs = code(m.URL) + " (bridged)"
				for _, h := range sortedKeys(m.Headers) {
					if names := config.Placeholders(m.Headers[h]); len(names) > 0 {
						creds = append(creds, h+" ← "+strings.Join(names, ", "))
					}
				}
			}
			for _, v := range sortedKeys(m.Env) {
				creds = append(creds, v+" ← "+m.Env[v])
			}
			if len(m.Harnesses) > 0 {
				runs += " (" + strings.Join(m.Harnesses, ", ") + " only)"
			}
			cells := []string{code(name), cell(runs), cell(strings.Join(creds, ", "))}
			for _, h := range harnesses {
				cells = append(cells, state(h, name))
			}
			row(cells...)
		}
	}
	for _, h := range harnesses {
		var clear []string
		for _, e := range h.Unmanaged {
			if len(e.Leaks) > 0 {
				clear = append(clear, fmt.Sprintf("%s (%s)", code(e.Name), strings.Join(e.Leaks, ", ")))
			}
		}
		if len(clear) > 0 {
			fmt.Fprintf(&b, "\n%s still holds credentials in clear in %s: %s. Move them with `passess migrate mcp %s NAME`.\n",
				h.Label, code(short(h.Config)), strings.Join(clear, ", "), h.ID)
		}
	}

	if len(u.Profiles) > 0 {
		fmt.Fprintf(&b, "\n## Profiles\n\nStarted with `passess run PROFILE -- PROGRAM`.\n\n")
		row("Profile", "Secrets", "Required", "Programs")
		row("---", "---", "---", "---")
		for _, name := range sortedKeys(u.Profiles) {
			p := u.Profiles[name]
			row(code(name), cell(strings.Join(p.Secrets, ", ")), cell(strings.Join(p.Required, ", ")), cell(strings.Join(p.Allow, ", ")))
		}
	}

	type boot struct{ backend, what, where string }
	var boots []boot
	addBoot := func(backend, what string, r *ref.Ref, fallback string) {
		switch {
		case r != nil:
			boots = append(boots, boot{backend, what, code(r.String())})
			noteKeychain(*r, backend+" "+what)
		case fallback != "":
			boots = append(boots, boot{backend, what, fallback})
		}
	}
	used := map[string]bool{}
	for _, s := range u.Secrets {
		for _, r := range s.Refs {
			used[r.Scheme] = true
		}
	}
	if used[ref.BWS] || u.Backends.BWS.AccessToken != nil {
		addBoot("Bitwarden Secrets Manager", "machine-account access token", u.Backends.BWS.AccessToken, "`BWS_ACCESS_TOKEN`")
	}
	if used[ref.Vault] || u.Backends.Vault.Token != nil {
		addBoot("Vault / OpenBao", "token", u.Backends.Vault.Token, "`VAULT_TOKEN`, `BAO_TOKEN` or `~/.vault-token`")
	}
	if used[ref.Bitwarden] || u.Backends.BW.Session != nil {
		addBoot("Bitwarden", "unlocked session key", u.Backends.BW.Session, "`BW_SESSION` from `bw unlock`")
	}
	if used[ref.OnePassword] {
		account := "the default account"
		if u.Backends.OP.Account != "" {
			account = code(u.Backends.OP.Account)
		}
		boots = append(boots, boot{"1Password", "desktop app sign-in", account + " (or `OP_SERVICE_ACCOUNT_TOKEN`)"})
	}
	if len(boots) > 0 {
		fmt.Fprintf(&b, "\n## Backend credentials\n\npassess reads these to reach the vaults; it never passes them to a program.\n\n")
		row("Backend", "Credential", "Where")
		row("---", "---", "---")
		for _, bt := range boots {
			row(bt.backend, bt.what, bt.where)
		}
	}

	if len(items) > 0 {
		sort.Slice(items, func(i, j int) bool {
			return items[i].service+"/"+items[i].account < items[j].service+"/"+items[j].account
		})
		fmt.Fprintf(&b, "\n## Keychain items\n\n")
		row("Service", "Account", "For")
		row("---", "---", "---")
		for _, it := range items {
			row(code(it.service), code(it.account), cell(it.use))
		}
		if argv := keychainPrompt("ACCOUNT"); argv != nil {
			fmt.Fprintf(&b, "\nTo change one, type the new value into `%s`.\n", shellLine(argv))
		}
	}

	var files [][2]string
	for _, c := range scan.CredentialFiles {
		p := filepath.Join(home, c.Path)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			files = append(files, [2]string{fmt.Sprintf("%s | %04o", code(short(p)), st.Mode().Perm()), c.Holds})
		}
	}
	if len(files) > 0 {
		fmt.Fprintf(&b, "\n## Credential files on this machine\n\nTools keep these themselves; passess does not manage them. `passess audit` checks their modes.\n\n")
		row("File", "Mode", "Holds")
		row("---", "---", "---")
		for _, f := range files {
			b.WriteString("| " + f[0] + " | " + cell(f[1]) + " |\n")
		}
	}

	fmt.Fprintf(&b, "\n## Changing a value\n\nChange it where it lives (the vault, or the keychain command above). passess reads the new value the next time a program asks;\n")
	b.WriteString("programs already started with `passess run` or `mcp-exec` keep the old one until they restart. If a value was ever in a file, a transcript\n")
	b.WriteString("or a chat, rotate it at its provider first: `passess scan --transcripts` shows where it went.\n")
	return b.String()
}
