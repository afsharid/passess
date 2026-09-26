package redact

import (
	"io"
	"sync"
)

// Writer redacts everything written to it before passing it on. It holds back
// only bytes that could be the beginning of a secret, so ordinary output is not
// delayed. Close must be called to flush what is held back. Writes and Close
// may be called from several goroutines.
type Writer struct {
	mu  sync.Mutex
	r   *Redactor
	w   io.Writer
	buf []byte
	out []byte
	err error
}

// NewWriter returns a Writer that redacts into w.
func (r *Redactor) NewWriter(w io.Writer) *Writer { return &Writer{r: r, w: w} }

// Write never reports a short write for data it accepted: held-back bytes are
// written by a later Write or by Close.
func (x *Writer) Write(p []byte) (int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.err != nil {
		return 0, x.err
	}
	x.buf = append(x.buf, p...)
	if err := x.flush(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close writes whatever is still held back and clears the internal buffers,
// which may hold part of a secret.
func (x *Writer) Close() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	err := x.flush(true)
	clear(x.buf[:cap(x.buf)])
	clear(x.out[:cap(x.out)])
	x.buf, x.out = nil, nil
	return err
}

func (x *Writer) flush(final bool) error {
	if x.err != nil {
		return x.err
	}
	out, n := x.r.process(x.out[:0], x.buf, final)
	if out == nil {
		out = x.buf[:n]
	} else {
		x.out = out
	}
	if len(out) > 0 {
		if _, err := x.w.Write(out); err != nil {
			x.err = err
			return err
		}
	}
	rest := copy(x.buf, x.buf[n:])
	clear(x.buf[rest:])
	x.buf = x.buf[:rest]
	return nil
}
