package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/provider"
	"github.com/afsharid/passess/internal/ref"
)

func init() {
	commands["browse"] = command{"list what a backend holds, by name only: `browse op` (vaults, items, fields) or `browse keychain`", runBrowse}
}

// browseRunner runs op and security(1) for browse; tests replace it.
var browseRunner provider.Runner = provider.ExecRunner{}

// browseGOOS is runtime.GOOS; tests replace it.
var browseGOOS = runtime.GOOS

// opEntry is a 1Password vault, item or field as browse lists it: names and
// the reference `passess add` takes, never a value.
type opEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category,omitempty"` // items: LOGIN, API_CREDENTIAL, …
	Section  string `json:"section,omitempty"`  // fields: the section's label
	Type     string `json:"type,omitempty"`     // fields: CONCEALED, STRING, …
	Ref      string `json:"ref,omitempty"`      // fields: op://vault/item/[section/]field
	UsedBy   string `json:"used_by,omitempty"`  // fields: the passess secret with that reference
}

type opBrowseOutput struct {
	Vault  string    `json:"vault,omitempty"` // the vault listed, "" for the vault list
	Item   string    `json:"item,omitempty"`  // the item whose fields are listed
	Vaults []opEntry `json:"vaults,omitempty"`
	Items  []opEntry `json:"items,omitempty"`
	Fields []opEntry `json:"fields,omitempty"`
}

// opVault, opItem and opField decode op's JSON. They have no field for a
// value: `op item get` sends every value of the item along, and decoding into
// these types drops them before they become Go strings.
type opVault struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type opItem struct {
	ID       string  `json:"id"`
	Title    string  `json:"title"`
	Category string  `json:"category"`
	Vault    opVault `json:"vault"`
	Fields   []struct {
		ID      string `json:"id"`
		Label   string `json:"label"`
		Type    string `json:"type"`
		Purpose string `json:"purpose"`
		Section *struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"section"`
		Reference string `json:"reference"`
	} `json:"fields"`
}

type keychainEntry struct {
	Account  string `json:"account"`
	Ref      string `json:"ref"`
	Modified string `json:"modified,omitempty"` // RFC 3339
	UsedBy   string `json:"used_by,omitempty"`
}

type keychainBrowseOutput struct {
	Service string          `json:"service"`
	Items   []keychainEntry `json:"items"`
}

func runBrowse(st *Streams, args []string) int {
	usage := func() int {
		fmt.Fprintln(st.Stderr, "Usage: passess browse op [--vault VAULT [--item ITEM]] [--json]")
		fmt.Fprintln(st.Stderr, "       passess browse keychain [--json]")
		fmt.Fprintln(st.Stderr, "Names only: no value is read into the output.")
		return ExitUsage
	}
	if len(args) == 0 {
		return usage()
	}
	fs := flag.NewFlagSet("browse", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	vault, item := new(string), new(string)
	if args[0] == "op" {
		vault = fs.String("vault", "", "list this vault's items (name or ID)")
		item = fs.String("item", "", "list this item's fields (name or ID; needs --vault)")
	}
	if args[0] != "op" && args[0] != "keychain" {
		return usage()
	}
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 || (*item != "" && *vault == "") {
		return usage()
	}
	// What the vault holds is the user's to see, as discover's list is.
	if code := refuseUnderAgent(st, "browse", "lists what your vault holds"); code != 0 {
		return code
	}
	u, _, code := loadConfigOrEmpty(st)
	if code != 0 {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if args[0] == "keychain" {
		return browseKeychain(ctx, st, u, *asJSON)
	}
	return browseOP(ctx, st, u, *vault, *item, *asJSON)
}

// runOP runs op with args and returns its stdout, which the caller decodes
// and clears.
func runOP(ctx context.Context, st *Streams, u *config.User, args ...string) ([]byte, error) {
	if u.Backends.OP.Account != "" {
		args = append(args, "--account", u.Backends.OP.Account)
	}
	res, err := browseRunner.Run(ctx, provider.Cmd{Name: "op", Args: append(args, "--format", "json"), Env: opEnv(st.Getenv)})
	if err != nil {
		return nil, err
	}
	if res.Exit != 0 {
		clear(res.Stdout)
		return nil, fmt.Errorf("op exited %d: %s", res.Exit, provider.CLIMessage(res.Stderr))
	}
	return res.Stdout, nil
}

// opEnv is the environment op runs with: what resolving an op:// reference
// gets, so the desktop app's unlock and a service account work the same.
func opEnv(getenv func(string) string) []string {
	env := provider.BaseEnv(getenv)
	for _, k := range []string{"OP_SERVICE_ACCOUNT_TOKEN", "OP_ACCOUNT", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_BIOMETRIC_UNLOCK_ENABLED"} {
		if v := getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func browseOP(ctx context.Context, st *Streams, u *config.User, vault, item string, asJSON bool) int {
	out := opBrowseOutput{Vault: vault, Item: item}
	var err error
	switch {
	case vault == "":
		out.Vaults, err = opVaults(ctx, st, u)
	case item == "":
		out.Items, err = opItems(ctx, st, u, vault)
	default:
		out.Fields, err = opFields(ctx, st, u, vault, item)
	}
	if err != nil {
		return failf(st, ExitUnavailable, "1Password: %v", err)
	}
	if asJSON {
		if out.Vaults == nil && vault == "" {
			out.Vaults = []opEntry{}
		}
		if out.Items == nil && vault != "" && item == "" {
			out.Items = []opEntry{}
		}
		if out.Fields == nil && item != "" {
			out.Fields = []opEntry{}
		}
		return writeJSON(st, out)
	}
	w := tabwriter.NewWriter(st.Stdout, 0, 4, 2, ' ', 0)
	switch {
	case vault == "":
		fmt.Fprintln(w, "VAULT\tID")
		for _, v := range out.Vaults {
			fmt.Fprintf(w, "%s\t%s\n", vaultName(v.Name), vaultName(v.ID))
		}
	case item == "":
		fmt.Fprintln(w, "ITEM\tCATEGORY\tID")
		for _, it := range out.Items {
			fmt.Fprintf(w, "%s\t%s\t%s\n", vaultName(it.Name), vaultName(it.Category), vaultName(it.ID))
		}
	default:
		fmt.Fprintln(w, "FIELD\tSECTION\tTYPE\tREFERENCE\tUSED BY")
		for _, f := range out.Fields {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", vaultName(f.Name), vaultName(f.Section), vaultName(f.Type), vaultName(f.Ref), f.UsedBy)
		}
	}
	_ = w.Flush()
	return ExitOK
}

func opVaults(ctx context.Context, st *Streams, u *config.User) ([]opEntry, error) {
	raw, err := runOP(ctx, st, u, "vault", "list")
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var vaults []opVault
	if err := json.Unmarshal(raw, &vaults); err != nil {
		return nil, fmt.Errorf("reading op vault list: %w", err)
	}
	out := make([]opEntry, 0, len(vaults))
	for _, v := range vaults {
		out = append(out, opEntry{ID: v.ID, Name: v.Name})
	}
	return out, nil
}

func opItems(ctx context.Context, st *Streams, u *config.User, vault string) ([]opEntry, error) {
	raw, err := runOP(ctx, st, u, "item", "list", "--vault", vault)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var items []opItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("reading op item list: %w", err)
	}
	out := make([]opEntry, 0, len(items))
	for _, it := range items {
		out = append(out, opEntry{ID: it.ID, Name: it.Title, Category: it.Category})
	}
	return out, nil
}

// opFields lists an item's fields. `op item get` answers with every value in
// the item; they are dropped while decoding and the raw answer is cleared.
func opFields(ctx context.Context, st *Streams, u *config.User, vault, item string) ([]opEntry, error) {
	raw, err := runOP(ctx, st, u, "item", "get", item, "--vault", vault)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var it opItem
	if err := json.Unmarshal(raw, &it); err != nil {
		return nil, fmt.Errorf("reading op item get: %w", err)
	}
	used := usedRefs(u)
	out := make([]opEntry, 0, len(it.Fields))
	for _, f := range it.Fields {
		e := opEntry{ID: f.ID, Name: f.Label, Type: f.Type}
		if e.Name == "" {
			e.Name = f.ID
		}
		if f.Section != nil {
			e.Section = f.Section.Label
		}
		if r, err := ref.Parse(f.Reference); err == nil && r.Scheme == ref.OnePassword {
			e.Ref = r.String()
			e.UsedBy = used[e.Ref]
		}
		out = append(out, e)
	}
	return out, nil
}

// usedRefs maps each configured reference to the secret that has it.
func usedRefs(u *config.User) map[string]string {
	used := map[string]string{}
	for _, name := range sortedKeys(u.Secrets) {
		for _, r := range u.Secrets[name].Refs {
			if _, ok := used[r.String()]; !ok {
				used[r.String()] = name
			}
		}
	}
	return used
}

func browseKeychain(ctx context.Context, st *Streams, u *config.User, asJSON bool) int {
	if browseGOOS != "darwin" {
		return failf(st, ExitUnavailable, "browse keychain is supported on macOS only")
	}
	// No -d: security(1) then prints attributes, never the data.
	res, err := browseRunner.Run(ctx, provider.Cmd{Name: "security", Args: []string{"dump-keychain"}, Env: provider.BaseEnv(st.Getenv)})
	if err != nil {
		return failf(st, ExitUnavailable, "keychain: %v", err)
	}
	if res.Exit != 0 {
		return failf(st, ExitUnavailable, "keychain: security exited %d: %s", res.Exit, provider.CLIMessage(res.Stderr))
	}
	out := keychainBrowseOutput{Service: keychainService, Items: keychainItems(res.Stdout, keychainService)}
	used := usedRefs(u)
	for i := range out.Items {
		out.Items[i].UsedBy = used[out.Items[i].Ref]
	}
	if asJSON {
		return writeJSON(st, out)
	}
	w := tabwriter.NewWriter(st.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ACCOUNT\tREFERENCE\tUSED BY")
	for _, it := range out.Items {
		fmt.Fprintf(w, "%s\t%s\t%s\n", it.Account, it.Ref, it.UsedBy)
	}
	_ = w.Flush()
	return ExitOK
}

// keychainItems reads `security dump-keychain` and returns the generic
// passwords of service, sorted by account. An account that is not a plain
// quoted name (security prints those in hex) is left out: a reference
// could not name it.
func keychainItems(dump []byte, service string) []keychainEntry {
	out := []keychainEntry{}
	seen := map[string]bool{}
	var class, svce, acct, mdat string
	flush := func() {
		if class == "genp" && svce == service && acct != "" && keychainAccountOK(acct) && !seen[acct] {
			seen[acct] = true
			e := keychainEntry{Account: acct, Ref: ref.Keychain + "://" + service + "/" + acct}
			if t, err := time.Parse("20060102150405Z", mdat); err == nil {
				e.Modified = t.UTC().Format(time.RFC3339)
			}
			out = append(out, e)
		}
		class, svce, acct, mdat = "", "", "", ""
	}
	sc := bufio.NewScanner(bytes.NewReader(dump))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "keychain: "):
			flush()
		case strings.HasPrefix(line, "class: "):
			class = unquote(strings.TrimPrefix(line, "class: "))
		case strings.HasPrefix(line, `"svce"<blob>=`):
			svce = unquote(strings.TrimPrefix(line, `"svce"<blob>=`))
		case strings.HasPrefix(line, `"acct"<blob>=`):
			acct = unquote(strings.TrimPrefix(line, `"acct"<blob>=`))
		case strings.HasPrefix(line, `"mdat"<timedate>=`):
			// 0x3230…5A00  "20261019193948Z\000"
			if _, text, ok := strings.Cut(line, `  "`); ok && len(text) >= 15 {
				mdat = text[:15]
			}
		}
	}
	flush()
	slices.SortFunc(out, func(a, b keychainEntry) int { return strings.Compare(a.Account, b.Account) })
	return out
}

const keychainAccountChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"

// keychainAccountOK is an account a keychain:// reference can name.
func keychainAccountOK(a string) bool {
	if len(a) == 0 || len(a) > 128 {
		return false
	}
	for _, c := range a {
		if !strings.ContainsRune(keychainAccountChars, c) {
			return false
		}
	}
	return true
}

// unquote returns a "quoted" security(1) value, or "" for hex and <NULL>.
func unquote(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return ""
	}
	if v, err := strconv.Unquote(s); err == nil {
		return v
	}
	return s[1 : len(s)-1]
}
