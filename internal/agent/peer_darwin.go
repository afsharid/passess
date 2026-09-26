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
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED) //nolint:gosec // G115: a descriptor fits in int
		if err != nil {
			perr = err
			return
		}
		p.UID = int(cred.Uid)
		p.PID, _ = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID) //nolint:gosec // G115: as above
	})
	if err == nil {
		err = perr
	}
	return p, err
}

// Harden keeps the agent's memory, which holds cached values, out of core
// dumps and away from debuggers that attach later (PT_DENY_ATTACH).
func Harden() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	return unix.PtraceDenyAttach()
}
