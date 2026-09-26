package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Listener accepts connections from processes of the user running it.
type Listener struct {
	l     *net.UnixListener
	path  string
	lock  *os.File
	once  sync.Once
	uid   int
	peers func(*net.UnixConn) (Peer, error)
}

// Listen serves the socket at path. One agent serves a path at a time: a lock
// file beside the socket, held for the listener's life, decides; a second
// Listen returns ErrRunning. A socket left behind by an agent that died is
// replaced; anything at path that is not a socket is left alone.
func Listen(path string) (*Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor fits in int
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w on %s", ErrRunning, path)
		}
		return nil, err
	}
	fail := func(err error) (*Listener, error) {
		_ = lock.Close()
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fail(fmt.Errorf("%s exists and is not a socket; not touching it", path))
		}
		// The lock is ours, so whatever made this socket is gone.
		if err := os.Remove(path); err != nil {
			return fail(err)
		}
	}
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ul.Close()
		return fail(err)
	}
	return &Listener{l: ul, path: path, lock: lock, uid: os.Getuid(), peers: peerOf}, nil
}

// Accept waits for the next connection from a process of this user.
// Connections from anyone else are closed unanswered.
func (l *Listener) Accept() (*Conn, error) {
	for {
		c, err := l.l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		p, err := l.peers(c)
		if err != nil || p.UID != l.uid {
			_ = c.Close()
			continue
		}
		conn := newConn(c)
		conn.Peer = p
		return conn, nil
	}
}

// Path is the socket's path.
func (l *Listener) Path() string { return l.path }

// Close stops accepting, removes the socket and only then releases the lock,
// so a new agent that starts meanwhile never loses its socket to this one.
func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		err = l.l.Close() // removes the socket file: net made it
		if cerr := l.lock.Close(); err == nil {
			err = cerr
		}
	})
	return err
}
