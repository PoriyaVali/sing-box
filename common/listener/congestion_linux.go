package listener

import (
	"sync"
	"syscall"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

var congestionWarned sync.Map // name -> struct{}

// congestionControl sets TCP_CONGESTION on the socket. As root (CAP_NET_ADMIN)
// the kernel loads the module on demand, so "bbr" works on a stock kernel with
// no sysctl change. It never fails the listen: a kernel without the algorithm
// keeps its default, and the reason is logged once.
func congestionControl(name string, log logger.ContextLogger) control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		var sockErr error
		if err := conn.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, name)
		}); err != nil {
			return nil
		}
		if sockErr != nil && log != nil {
			if _, seen := congestionWarned.LoadOrStore(name, struct{}{}); !seen {
				log.Warn("tcp_congestion ", name, " unavailable, keeping the system default: ", sockErr)
			}
		}
		return nil
	}
}
