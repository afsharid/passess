package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// maxRequest bounds the request line: an environment is tens of kilobytes, a
// tool output to mask (MaxRedact) is larger.
const maxRequest = 4*MaxRedact + 1<<20

// MaxRedact is the longest text a Redact request carries. JSON may escape a
// byte into six, hence the room maxRequest leaves.
const MaxRedact = 4 << 20

// maxFrame bounds every later line.
const maxFrame = 64 << 10

// Conn is one client connection, seen from either end.
type Conn struct {
	c    *net.UnixConn
	r    *bufio.Reader
	wmu  sync.Mutex
	Peer Peer // the other end; set on the agent's side
}

// Peer is the process at the other end of a connection.
type Peer struct {
	UID int
	PID int
}

// Dial connects to the agent at path. It returns an error wrapping
// ErrNotRunning when nothing listens there.
func Dial(path string) (*Conn, error) {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("%w (no one listens on %s)", ErrNotRunning, path)
		}
		return nil, err
	}
	return newConn(c), nil
}

func newConn(c *net.UnixConn) *Conn {
	return &Conn{c: c, r: bufio.NewReaderSize(c, 4096)}
}

// Send sends the request, with files attached (an exec request's stdin,
// stdout and stderr, in that order).
func (c *Conn) Send(req Request, files []*os.File) error {
	if len(files) > 255 {
		return errors.New("too many files")
	}
	var oob []byte
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, f := range files {
			fds[i] = int(f.Fd()) //nolint:gosec // G115: descriptors are small non-negative ints
		}
		oob = syscall.UnixRights(fds...)
	}
	// A one-byte preamble carries the descriptors, so they arrive with a
	// known byte and never with part of the JSON.
	c.wmu.Lock()
	_, _, err := c.c.WriteMsgUnix([]byte{byte(len(files))}, oob, nil) //nolint:gosec // G115: len(files) <= 255, checked above
	c.wmu.Unlock()
	if err != nil {
		return err
	}
	return c.Write(req)
}

// Receive reads a request and the files attached to it. The files are
// close-on-exec, so no other child the agent starts inherits them.
func (c *Conn) Receive(timeout time.Duration) (Request, []*os.File, error) {
	var req Request
	if err := c.c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return req, nil, err
	}
	files, err := c.receiveFiles()
	if err != nil {
		return req, nil, err
	}
	if err := c.read(&req, maxRequest); err != nil {
		closeAll(files)
		return req, nil, err
	}
	if err := c.c.SetReadDeadline(time.Time{}); err != nil {
		closeAll(files)
		return req, nil, err
	}
	return req, files, nil
}

func (c *Conn) receiveFiles() ([]*os.File, error) {
	raw, err := c.c.SyscallConn()
	if err != nil {
		return nil, err
	}
	pre := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	var n, oobn, flags int
	var fds []int
	var rerr error
	err = raw.Read(func(fd uintptr) bool {
		// Received descriptors are not close-on-exec until set so. Holding
		// ForkLock while receiving and marking them keeps a concurrent fork
		// from copying them into another child. The read does not block:
		// the poller calls this only when the socket is readable.
		syscall.ForkLock.RLock()
		defer syscall.ForkLock.RUnlock()
		n, oobn, flags, _, rerr = syscall.Recvmsg(int(fd), pre, oob, 0) //nolint:gosec // G115: a descriptor fits in int
		if errors.Is(rerr, syscall.EAGAIN) || errors.Is(rerr, syscall.EINTR) {
			return false
		}
		if rerr == nil && oobn > 0 {
			msgs, perr := syscall.ParseSocketControlMessage(oob[:oobn])
			if perr != nil {
				rerr = perr
				return true
			}
			for i := range msgs {
				got, perr := syscall.ParseUnixRights(&msgs[i])
				if perr != nil {
					rerr = perr
					continue
				}
				for _, d := range got {
					syscall.CloseOnExec(d)
				}
				fds = append(fds, got...)
			}
		}
		return true
	})
	files := make([]*os.File, len(fds))
	for i, d := range fds {
		files[i] = os.NewFile(uintptr(d), fmt.Sprintf("client-fd-%d", i)) //nolint:gosec // G115: d came from the kernel
	}
	switch {
	case err != nil:
	case rerr != nil:
		err = rerr
	case n == 0:
		err = io.ErrUnexpectedEOF
	case flags&syscall.MSG_CTRUNC != 0:
		err = errors.New("the client sent more descriptors than expected")
	case int(pre[0]) != len(files):
		err = fmt.Errorf("the client announced %d descriptors and sent %d", pre[0], len(files))
	}
	if err != nil {
		closeAll(files)
		return nil, err
	}
	return files, nil
}

// Write sends one JSON line.
func (c *Conn) Write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.c.Write(append(b, '\n'))
	return err
}

// ReadFrame reads the next frame.
func (c *Conn) ReadFrame() (Frame, error) {
	var f Frame
	err := c.read(&f, maxFrame)
	return f, err
}

func (c *Conn) read(v any, limit int) error {
	var line []byte
	for {
		chunk, err := c.r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > limit {
			return fmt.Errorf("message longer than %d bytes", limit)
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return json.Unmarshal(line, v)
}

// Close closes the connection.
func (c *Conn) Close() error { return c.c.Close() }

// SetDeadline bounds how long reads and writes on the connection may wait.
func (c *Conn) SetDeadline(t time.Time) error { return c.c.SetDeadline(t) }

func closeAll(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}
