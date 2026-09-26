//go:build !linux

package listener

import (
	"syscall"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
)

// TCP_CONGESTION is Linux-only; elsewhere the option is accepted and ignored.
func congestionControl(string, logger.ContextLogger) control.Func {
	return func(string, string, syscall.RawConn) error { return nil }
}
