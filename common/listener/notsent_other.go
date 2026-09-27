//go:build !linux

package listener

import (
	"net"

	"github.com/sagernet/sing/common/logger"
)

// TCP_NOTSENT_LOWAT is set only on Linux; elsewhere the option is ignored.
func setNotSentLowat(net.Conn, int, logger.ContextLogger) {}
