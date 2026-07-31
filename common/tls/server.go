package tls

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/common/badtls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ServerOptions struct {
	Context        context.Context
	Logger         log.ContextLogger
	Options        option.InboundTLSOptions
	KTLSCompatible bool
}

func NewServer(ctx context.Context, logger log.ContextLogger, options option.InboundTLSOptions) (ServerConfig, error) {
	return NewServerWithOptions(ServerOptions{
		Context: ctx,
		Logger:  logger,
		Options: options,
	})
}

func NewServerWithOptions(options ServerOptions) (ServerConfig, error) {
	if !options.Options.Enabled {
		return nil, nil
	}
	if !options.KTLSCompatible {
		if options.Options.KernelTx {
			options.Logger.Warn("enabling kTLS TX in current scenarios will definitely reduce performance, please checkout https://sing-box.sagernet.org/configuration/shared/tls/#kernel_tx")
		}
	}
	if options.Options.KernelRx {
		options.Logger.Warn("enabling kTLS RX will definitely reduce performance, please checkout https://sing-box.sagernet.org/configuration/shared/tls/#kernel_rx")
	}
	if options.Options.Reality != nil && options.Options.Reality.Enabled {
		return NewRealityServer(options.Context, options.Logger, options.Options)
	}
	return NewSTDServer(options.Context, options.Logger, options.Options)
}

// ServerHandshake completes the TLS handshake for an inbound connection.
//
// The deadline is TLSHandshakeTimeout rather than the general TCPTimeout, which
// is 15s and was cutting off real users. A handshake that loses a packet is
// retried by TCP with exponential backoff - roughly 1s, 3s, 7s, 15s - so a
// client on a network that drops one or two packets lands almost exactly on the
// old limit and is dropped at the worst possible moment, having already paid the
// cost of getting that far. On the networks this is deployed to, that is not a
// rare event; it accounted for a quarter of all failed handshakes on a node.
//
// Still bounded, and deliberately: a peer that connects and stays silent holds a
// goroutine and a socket for the whole window, which is a cheap way to exhaust a
// node, and these nodes are probed continuously. 60s matches nginx's long-
// standing ssl_handshake_timeout default - the same trade-off, answered by
// people who have watched it in production far longer than we have.
//
// TCPTimeout is left alone. Sixteen other places share it - dialling, urltest,
// websocket deadlines, HTTP transports - and none of them are asking this
// question.
func ServerHandshake(ctx context.Context, conn net.Conn, config ServerConfig) (Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, C.TLSHandshakeTimeout)
	defer cancel()
	tlsConn, err := aTLS.ServerHandshake(ctx, conn, config)
	if err != nil {
		return nil, err
	}
	readWaitConn, err := badtls.NewReadWaitConn(tlsConn)
	if err == nil {
		return readWaitConn, nil
	} else if err != os.ErrInvalid {
		return nil, err
	}
	return tlsConn, nil
}
