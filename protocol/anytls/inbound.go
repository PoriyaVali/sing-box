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
	"github.com/sagernet/sing/common/bufio"
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
	sessions     sync.Map
	usersAccess  sync.RWMutex
	users        map[string]*inboundUser
	closed       bool
	uuidlist     []string
	fallbackAddr M.Socksaddr
}

type inboundUser struct {
	option.AnyTLSUser
}

type sessionContextKey struct{}

type inboundSession struct {
	users map[string]*inboundUser
	conn  net.Conn
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeAnyTLS, tag),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		users:   make(map[string]*inboundUser, len(options.Users)),
	}
	for index, user := range options.Users {
		if _, exists := inbound.users[user.Name]; exists {
			return nil, E.New("duplicate name for AnyTLS user ", index)
		}
		inbound.users[user.Name] = &inboundUser{AnyTLSUser: user}
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
	// The V2bX-patched service exposes the physical session immediately after
	// authentication. Keep source compatibility with the original module; its
	// stream handler below performs the same admission check on first use.
	if authenticated, ok := any(service).(interface {
		SetAuthenticatedSessionHandler(func(context.Context, net.Conn) (func(), error))
	}); ok {
		authenticated.SetAuthenticatedSessionHandler(inbound.authenticatedSession)
	}
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
	h.usersAccess.Lock()
	h.closed = true
	h.users = nil
	var conns []net.Conn
	h.sessions.Range(func(key, _ any) bool {
		h.sessions.Delete(key)
		conns = append(conns, key.(net.Conn))
		return true
	})
	h.usersAccess.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return common.Close(h.listener, h.tlsConfig)
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.usersAccess.RLock()
	if h.closed {
		h.usersAccess.RUnlock()
		N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	session := &inboundSession{users: h.users}
	h.sessions.Store(conn, struct{}{})
	h.usersAccess.RUnlock()
	defer h.sessions.Delete(conn)
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	session.conn = conn
	ctx = context.WithValue(ctx, sessionContextKey{}, session)
	// service.NewConnection runs the whole session and returns only when it is
	// over, so this is the one exit every session takes. The entry used to be
	// removed from the onClose passed down - but sing-anytls hands that onClose
	// to each STREAM, never to the session. A session that ended without ever
	// opening a stream (a device dropping right after the handshake, all the
	// time on mobile networks) never called it, and its entry, holding the TLS
	// connection and its buffers, stayed until the process restarted: a node's
	// memory grew with uptime.
	defer h.userconns.Delete(conn)
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func (h *Inbound) authenticatedSession(ctx context.Context, _ net.Conn) (func(), error) {
	session, ok := ctx.Value(sessionContextKey{}).(*inboundSession)
	if !ok {
		return nil, E.New("missing AnyTLS session context")
	}
	name, authenticated := auth.UserFromContext[string](ctx)
	identity := session.users[name]
	h.usersAccess.RLock()
	defer h.usersAccess.RUnlock()
	if !authenticated || identity == nil || h.closed || h.users[name] != identity {
		return nil, E.New("AnyTLS user generation is no longer active")
	}
	h.userconns.Store(session.conn, identity)
	return func() { h.userconns.Delete(session.conn) }, nil
}

// fallbackConnection hands a connection that failed authentication to the
// configured site, so the port answers like the host its certificate names
// instead of closing.
//
// Dialled directly rather than handed to the connection router, which is what
// the trojan inbound does. The router would sniff the connection, and a
// deployment with sniff_override_destination on — V2bX turns it on for every
// inbound — rewrites the destination to the sniffed Host header. The fallback
// target then becomes whatever hostname the prober asked for, on the fallback
// port, which resolves to nothing and hangs: the exact symptom that made the
// first build of this look like a no-op from outside. Routing would also drag
// the connection through every route rule, so a "reject private destinations"
// rule would silently kill a loopback decoy.
//
// A local, fixed, operator-configured address needs none of that machinery.
func (h *Inbound) fallbackConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.logger.DebugContext(ctx, "fallback connection from ", metadata.Source, " to ", h.fallbackAddr)
	var dialer net.Dialer
	serverConn, err := dialer.DialContext(ctx, N.NetworkTCP, h.fallbackAddr.String())
	if err != nil {
		// Losing the disguise is bad; failing loudly is worse, so this closes
		// the way it did before the fallback existed rather than hanging.
		h.logger.ErrorContext(ctx, E.Cause(err, "fallback dial to ", h.fallbackAddr))
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	if err := bufio.CopyConn(ctx, conn, serverConn); err != nil {
		h.logger.DebugContext(ctx, E.Cause(err, "fallback connection closed"))
	}
	if onClose != nil {
		onClose(nil)
	}
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if _, err := (*Inbound)(h).authenticatedSession(ctx, nil); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
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
