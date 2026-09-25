package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/secret"
)

func mustNew(t testing.TB, kv ...string) *Redactor {
	t.Helper()
	var ss []Secret
	for i := 0; i < len(kv); i += 2 {
		ss = append(ss, Secret{Name: kv[i], Value: secret.FromString(kv[i+1])})
	}
	r, _, err := New(ss, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// naive is the reference: at each position take the longest pattern that
// matches, else copy one byte.
func naive(r *Redactor, b []byte) []byte {
	st := r.st()
	var out []byte
	for i := 0; i < len(b); {
		best := -1
		for j, p := range st.pats {
			if bytes.HasPrefix(b[i:], p) && (best < 0 || len(p) > len(st.pats[best])) {
				best = j
			}
		}
		if best < 0 {
			out = append(out, b[i])
			i++
			continue
		}
		out = append(out, st.repl[best]...)
		i += len(st.pats[best])
	}
	return out
}

func TestRedactRawValue(t *testing.T) {
	r := mustNew(t, "API_KEY", "passess-fake-0123456789abcdef")
	got := string(r.Redact([]byte("key=passess-fake-0123456789abcdef; again passess-fake-0123456789abcdef.")))
	want := "key=[REDACTED:API_KEY]; again [REDACTED:API_KEY]."
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRedactEncodings(t *testing.T) {
	const v = `p@ss w/rd+"<&>"=1234567890`
	r := mustNew(t, "DB_PASSWORD", v)

	jsonStd, _ := json.Marshal(map[string]string{"password": v})
	var noHTML bytes.Buffer
	enc := json.NewEncoder(&noHTML)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]string{"password": v})

	cases := map[string]string{
		"json":       string(jsonStd),
		"json-plain": noHTML.String(),
		"query":      "https://db.example/?password=" + url.QueryEscape(v) + "&x=1",
		"path":       "https://db.example/u/" + url.PathEscape(v) + "/x",
		"lower-pct":  "pw=" + strings.ToLower(url.QueryEscape(v)),
	}
	for off := range 3 {
		for _, e := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding} {
			blob := append([]byte("xyz"[:off]), v...)
			blob = append(blob, "trailing bytes"...)
			cases[fmt.Sprintf("base64-%d-%p", off, e)] = "Authorization: Basic " + e.EncodeToString(blob)
		}
	}
	for name, in := range cases {
		out := r.Redact([]byte(in))
		if !bytes.Contains(out, []byte("[REDACTED:DB_PASSWORD]")) {
			t.Errorf("%s: nothing redacted in %q", name, in)
		}
		for _, p := range variants([]byte(v)) {
			if bytes.Contains(out, p) {
				t.Errorf("%s: variant survived in %q", name, out)
			}
		}
		if bytes.Contains(out, []byte(v)) {
			t.Errorf("%s: raw value survived", name)
		}
	}
}

func TestRedactedJSONStaysValid(t *testing.T) {
	const v = `quote"slash\tab	newline` + "\n" + `end-of-value`
	r := mustNew(t, "TOKEN", v)
	doc, _ := json.Marshal(map[string]any{"result": map[string]string{"token": v, "note": "ok"}})
	out := r.Redact(doc)
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("redacted JSON does not parse: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "[REDACTED:TOKEN]") {
		t.Fatalf("not redacted: %s", out)
	}
}

func TestLeftmostLongest(t *testing.T) {
	r := mustNew(t, "SHORT", "abcdefgh", "LONG", "abcdefgh-and-more")
	got := string(r.Redact([]byte("<abcdefgh-and-more> <abcdefgh>")))
	if got != "<[REDACTED:LONG]> <[REDACTED:SHORT]>" {
		t.Fatalf("got %q", got)
	}
}

func TestNoMatchReturnsInput(t *testing.T) {
	r := mustNew(t, "API_KEY", "passess-fake-0123456789abcdef")
	in := []byte("nothing to see here")
	if out := r.Redact(in); &out[0] != &in[0] || len(out) != len(in) {
		t.Fatal("Redact must return its input when nothing matches")
	}
}

func TestLengthRules(t *testing.T) {
	_, _, err := New([]Secret{{Name: "PIN", Value: secret.FromString("123")}}, Options{})
	if !errors.Is(err, ErrTooShort) {
		t.Fatalf("3-byte value: err = %v, want ErrTooShort", err)
	}
	if strings.Contains(fmt.Sprint(err), "123") {
		t.Fatalf("error echoes the value: %v", err)
	}
	_, warn, err := New([]Secret{{Name: "CODE", Value: secret.FromString("abcd12")}}, Options{})
	if err != nil || len(warn) != 1 || strings.Contains(warn[0], "abcd12") {
		t.Fatalf("6-byte value: warn=%q err=%v", warn, err)
	}
	_, _, err = New([]Secret{{Name: "bad-name", Value: secret.FromString("abcdefgh")}}, Options{})
	if err == nil {
		t.Fatal("invalid name accepted")
	}
}

func TestStringHidesPatterns(t *testing.T) {
	r := mustNew(t, "API_KEY", "passess-fake-0123456789abcdef")
	type holder struct{ r *Redactor }
	type valueHolder struct{ r Redactor }
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d", "%q"} {
		for _, arg := range []any{r, *r, holder{r}, valueHolder{*r}} {
			s := fmt.Sprintf(verb, arg)
			if strings.Contains(s, "passess-fake") || strings.Contains(s, "112 97 115 115") || strings.Contains(s, "70617373") {
				t.Fatalf("printing a Redactor with %s leaked a pattern: %q", verb, s)
			}
		}
	}
}

func randomSecret(rng *rand.Rand) string {
	const alphabets = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=-_%&?\"\\<> "
	n := 8 + rng.IntN(40)
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabets[rng.IntN(len(alphabets))]
	}
	return string(b)
}

func randomDocument(rng *rand.Rand, values []string) []byte {
	var b bytes.Buffer
	for range 20 + rng.IntN(60) {
		switch rng.IntN(6) {
		case 0:
			v := values[rng.IntN(len(values))]
			b.WriteString(v)
		case 1:
			v := values[rng.IntN(len(values))]
			j, _ := json.Marshal(v)
			b.Write(j)
		case 2:
			v := values[rng.IntN(len(values))]
			b.WriteString(url.QueryEscape(v))
		case 3:
			v := values[rng.IntN(len(values))]
			pre := make([]byte, rng.IntN(5))
			b.WriteString(base64.StdEncoding.EncodeToString(append(pre, v...)))
		default:
			for range rng.IntN(30) {
				b.WriteByte(byte(32 + rng.IntN(95)))
			}
		}
		b.WriteByte("\n "[rng.IntN(2)])
	}
	return b.Bytes()
}

func writeChunked(t testing.TB, r *Redactor, doc []byte, rng *rand.Rand) []byte {
	var out bytes.Buffer
	w := r.NewWriter(&out)
	for i := 0; i < len(doc); {
		n := 1 + rng.IntN(64)
		if rng.IntN(10) == 0 {
			n = 1 + rng.IntN(4096)
		}
		n = min(n, len(doc)-i)
		if _, err := w.Write(doc[i : i+n]); err != nil {
			t.Fatal(err)
		}
		i += n
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// TestRandomChunkingMatchesWholeBuffer is the property the design depends on:
// any split of the input yields exactly the whole-buffer result, which in turn
// equals the naive reference, and no raw value survives.
func TestRandomChunkingMatchesWholeBuffer(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for iter := range 300 {
		var kv []string
		var values []string
		for i := range 1 + rng.IntN(4) {
			v := randomSecret(rng)
			values = append(values, v)
			kv = append(kv, fmt.Sprintf("S%d", i), v)
		}
		r := mustNew(t, kv...)
		doc := randomDocument(rng, values)

		whole := r.Redact(bytes.Clone(doc))
		if ref := naive(r, doc); !bytes.Equal(whole, ref) {
			t.Fatalf("iter %d: matcher differs from reference\n got %q\nwant %q", iter, whole, ref)
		}
		if chunked := writeChunked(t, r, doc, rng); !bytes.Equal(chunked, whole) {
			t.Fatalf("iter %d: chunked output differs\n got %q\nwant %q", iter, chunked, whole)
		}
		for _, v := range values {
			if bytes.Contains(whole, []byte(v)) {
				t.Fatalf("iter %d: raw value survived", iter)
			}
		}
	}
}

func FuzzWriterChunking(f *testing.F) {
	f.Add([]byte("prefix passess-fake-0123456789abcdef suffix"), uint64(7))
	f.Add([]byte("cGFzc2Vzcy1mYWtlLTAxMjM0NTY3ODlhYmNkZWY="), uint64(3))
	f.Add([]byte(`{"k":"passess-fake-0123456789abcdef"}`), uint64(1))
	r := mustNew(f, "A", "passess-fake-0123456789abcdef", "B", `we"ird/val+ue 42`)
	f.Fuzz(func(t *testing.T, doc []byte, seed uint64) {
		whole := r.Redact(bytes.Clone(doc))
		if ref := naive(r, doc); !bytes.Equal(whole, ref) {
			t.Fatalf("matcher differs from reference: %q vs %q", whole, ref)
		}
		chunked := writeChunked(t, r, doc, rand.New(rand.NewPCG(seed, seed^0x9e37)))
		if !bytes.Equal(chunked, whole) {
			t.Fatalf("chunked %q != whole %q", chunked, whole)
		}
	})
}

func BenchmarkRedact(b *testing.B) {
	r := mustNew(b, "A", "passess-fake-0123456789abcdef", "B", "passess-fake-ghs-0123456789", "C", "postgres://u:passess-fake-pw@db/app")
	rng := rand.New(rand.NewPCG(3, 4))
	doc := make([]byte, 5<<20)
	for i := range doc {
		doc[i] = byte(32 + rng.IntN(95))
	}
	b.SetBytes(int64(len(doc)))
	b.ResetTimer()
	for b.Loop() {
		_ = r.Redact(doc)
	}
}
