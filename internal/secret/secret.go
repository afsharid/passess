// Package secret holds secret values so that no formatting, encoding or logging
// path can print them.
//
// Every method fmt, encoding/json, encoding and log/slog consult returns
// "[REDACTED]". Reflection is the remaining path: when a Value sits in an
// unexported field of another struct, fmt walks it without calling methods. The
// bytes are therefore reachable only through an unsafe.Pointer, which fmt prints
// as an address, never as the bytes it points to.
package secret

import (
	"fmt"
	"io"
	"log/slog"
	"unsafe"
)

// Redacted is what every formatting path of a Value produces.
const Redacted = "[REDACTED]"

type payload struct {
	ptr unsafe.Pointer // first byte of the secret; keeps the array alive for the GC
	n   int
}

// Value is a secret. The zero Value is empty.
type Value struct{ p *payload }

// New copies b into a new Value; the caller may zero b afterwards.
func New(b []byte) Value {
	if len(b) == 0 {
		return Value{}
	}
	c := make([]byte, len(b))
	copy(c, b)
	return Value{&payload{ptr: unsafe.Pointer(unsafe.SliceData(c)), n: len(c)}} //nolint:gosec // G103: hides the bytes from reflection, see package doc
}

// FromString returns a Value holding s.
func FromString(s string) Value { return New([]byte(s)) }

// Bytes returns the secret itself. It exists for the one place a value must
// leave passess — the environment of the process that consumes it — and the
// result must never be logged, formatted or written anywhere else.
func (v Value) Bytes() []byte {
	if v.p == nil || v.p.n == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(v.p.ptr), v.p.n) //nolint:gosec // G103: ptr and n always describe one live allocation
}

// Len reports the length of the secret in bytes.
func (v Value) Len() int {
	if v.p == nil {
		return 0
	}
	return v.p.n
}

// Empty reports whether the Value holds no bytes.
func (v Value) Empty() bool { return v.Len() == 0 }

// Zero overwrites the secret's bytes and empties the Value. Copies made
// elsewhere, for example the strings of an exec.Cmd environment, are out of reach.
func (v Value) Zero() {
	if v.p == nil {
		return
	}
	clear(v.Bytes())
	v.p.ptr, v.p.n = nil, 0
}

func (Value) String() string   { return Redacted }
func (Value) GoString() string { return "secret.Value(" + Redacted + ")" }

// Format makes every verb, including %x, %q and %d, print Redacted.
func (Value) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, Redacted) }

func (Value) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }
func (Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil }
func (Value) LogValue() slog.Value         { return slog.StringValue(Redacted) }
