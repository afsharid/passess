package agent

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerOf(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var p Peer
	var perr error
	err = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) //nolint:gosec // G115: a descriptor fits in int
		if err != nil {
			perr = err
			return
		}
		p.UID, p.PID = int(cred.Uid), int(cred.Pid)
	})
	if err == nil {
		err = perr
	}
	return p, err
}

// Harden keeps the agent's memory, which holds cached values, out of core
// dumps and away from same-user ptrace (PR_SET_DUMPABLE).
func Harden() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
