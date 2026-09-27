package listener

import (
	"net"
	"sync/atomic"
	"syscall"

	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

var notSentLowatWarned atomic.Bool

// setNotSentLowat sets TCP_NOTSENT_LOWAT on an accepted connection. A failure
// never affects the connection; the reason is logged once.
func setNotSentLowat(conn net.Conn, bytes int, log logger.ContextLogger) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, bytes)
	}); err != nil {
		return
	}
	if sockErr != nil && log != nil && notSentLowatWarned.CompareAndSwap(false, true) {
		log.Warn("tcp_notsent_lowat unavailable, keeping the system default: ", sockErr)
	}
}
