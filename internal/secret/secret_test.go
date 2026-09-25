package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const plain = "s3cr3t-value-0123456789"

func assertClean(t *testing.T, where, out string) {
	t.Helper()
	if strings.Contains(out, plain) {
		t.Fatalf("%s leaked the value: %q", where, out)
	}
	// Byte-wise printing would show the first bytes as decimal numbers.
	if strings.Contains(out, "115 51 99 114") {
		t.Fatalf("%s leaked the value as bytes: %q", where, out)
	}
}

func TestFormattingNeverLeaks(t *testing.T) {
	v := FromString(plain)
	type exported struct{ S Value }
	type unexported struct{ s Value }
	type nested struct {
		In  unexported
		Ptr *Value
		All []Value
		By  map[string]Value
	}
	n := nested{In: unexported{v}, Ptr: &v, All: []Value{v, v}, By: map[string]Value{"k": v}}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T %v"} {
		assertClean(t, verb, fmt.Sprintf(verb, v))
		assertClean(t, verb+" pointer", fmt.Sprintf(verb, &v))
		assertClean(t, verb+" exported field", fmt.Sprintf(verb, exported{v}))
		assertClean(t, verb+" unexported field", fmt.Sprintf(verb, unexported{v}))
		assertClean(t, verb+" nested", fmt.Sprintf(verb, n))
	}
	assertClean(t, "Sprint", fmt.Sprint(v, &v, n))
	assertClean(t, "Sprintln", fmt.Sprintln(v, n))
	assertClean(t, "Errorf", fmt.Errorf("resolving: %v", v).Error())
	assertClean(t, "errors.Join", errors.Join(fmt.Errorf("a %s", v)).Error())

	j, err := json.Marshal(struct {
		S   Value
		P   *Value
		All []Value
		s   Value
	}{S: v, P: &v, All: []Value{v}, s: v})
	if err != nil {
		t.Fatal(err)
	}
	assertClean(t, "json", string(j))

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	logger.Info("resolved", "value", v, "ptr", &v, "struct", exported{v})
	slog.New(slog.NewTextHandler(&logs, nil)).Info("resolved", "value", v, "nested", n)
	assertClean(t, "slog", logs.String())
}

func TestPanicDoesNotLeak(t *testing.T) {
	if os.Getenv("PASSESS_SECRET_PANIC") == "1" {
		panic(FromString(plain))
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPanicDoesNotLeak$")
	cmd.Env = append(os.Environ(), "PASSESS_SECRET_PANIC=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("helper process did not panic")
	}
	if !strings.Contains(string(out), Redacted) {
		t.Fatalf("panic output does not show the redaction marker: %q", out)
	}
	assertClean(t, "panic", string(out))
}

func TestNewCopiesAndZeroClears(t *testing.T) {
	src := []byte(plain)
	v := New(src)
	clear(src)
	if string(v.Bytes()) != plain {
		t.Fatal("New must copy its input")
	}
	backing := v.Bytes()
	v.Zero()
	if v.Bytes() != nil || !v.Empty() {
		t.Fatal("Zero must empty the value")
	}
	for _, b := range backing {
		if b != 0 {
			t.Fatal("Zero must overwrite the backing bytes")
		}
	}
	var zero Value
	zero.Zero()
	if zero.Len() != 0 || zero.Bytes() != nil {
		t.Fatal("zero Value must be empty")
	}
}
