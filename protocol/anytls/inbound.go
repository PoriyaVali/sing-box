package anytls

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.AnyTLSInboundOptions](registry, C.TypeAnyTLS, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	tlsConfig    tls.ServerConfig
	router       adapter.ConnectionRouterEx
	logger       logger.ContextLogger
	listener     *listener.Listener
	service      *anytls.Service
	userconns    sync.Map
	uuidlist     []string
	fallbackAddr M.Socksaddr
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeAnyTLS, tag),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
	}

	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}

	paddingScheme := padding.DefaultPaddingScheme
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	}

	// sing-anytls has always accepted a fallback handler; upstream sing-box
	// simply never passed one, so every unauthenticated connection ended in
	// "fallback disabled" and an immediate close. That is a fingerprint: an
	// active prober completes the TLS handshake, sends an ordinary HTTP
	// request, and learns that whatever is here is not a web server. Handing
	// those connections to a local site instead makes the answer boring.
	//
	// It works because the library rewinds before falling back: it wraps the
	// connection with bufio.NewCachedConn and calls b.Resize(0, n) on failure,
	// so the fallback target receives the client's bytes from the first one —
	// a complete request, not a truncated one.
	var fallbackHandler N.TCPConnectionHandlerEx
	if options.Fallback != nil && options.Fallback.Server != "" {
		inbound.fallbackAddr = options.Fallback.Build()
		if !inbound.fallbackAddr.IsValid() {
			return nil, E.New("invalid fallback address: ", inbound.fallbackAddr)
		}
		fallbackHandler = adapter.NewUpstreamContextHandlerEx(inbound.fallbackConnection, nil)
	}

	service, err := anytls.NewService(anytls.ServiceConfig{
		Users: common.Map(options.Users, func(it option.AnyTLSUser) anytls.User {
			return (anytls.User)(it)
		}),
		PaddingScheme:   paddingScheme,
		Handler:         (*inboundHandler)(inbound),
		FallbackHandler: fallbackHandler,
		Logger:          logger,
	})
	if err != nil {
		return nil, err
	}
	inbound.service = service
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	uuidlist := make([]string, 0, len(options.Users))
	for _, user := range options.Users {
		uuidlist = append(uuidlist, user.Name)
	}
	inbound.userconns = sync.Map{}
	inbound.uuidlist = uuidlist
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return common.Close(h.listener, h.tlsConfig)
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	h.userconns.Store(conn, metadata.User)
	onClose = N.AppendClose(onClose, func(err error) {
		h.userconns.Delete(conn)
	})
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

// fallbackConnection hands a connection that failed authentication to the
// configured local site, so the port answers like the host its certificate
// names instead of closing. Routed through the normal connection router (the
// same path the trojan inbound uses) so the destination is dialled by the
// node's own outbound and shows up in the logs like any other connection.
func (h *Inbound) fallbackConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Destination = h.fallbackAddr
	// Debug, not Info: on a probed node this fires as often as the probes
	// arrive, and it is not news once the fallback is deliberately configured.
	h.logger.DebugContext(ctx, "fallback connection to ", h.fallbackAddr)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
