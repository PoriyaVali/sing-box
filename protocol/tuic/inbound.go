package tuic

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TUICInboundOptions](registry, C.TypeTUIC, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router       adapter.ConnectionRouterEx
	logger       log.ContextLogger
	listener     *listener.Listener
	tlsConfig    tls.ServerConfig
	server       *tuic.Service[*inboundUser]
	userNameList []string
	// Membership validation and connection registration share this lock, so
	// an authenticated session cannot register after its generation is removed.
	usersAccess sync.RWMutex
	users       map[string]*inboundUser
	userconns   sync.Map
	closed      bool
}

// The pointer identifies one authentication generation. Re-adding a UUID
// creates a new identity; old authenticated QUIC sessions remain revoked.
type inboundUser struct {
	option.TUICUser
	id int
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICInboundOptions) (adapter.Inbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeTUIC, tag),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		tlsConfig: tlsConfig,
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	service, err := tuic.NewService[*inboundUser](tuic.ServiceOptions{
		Context:           ctx,
		Logger:            logger,
		TLSConfig:         tlsConfig,
		CongestionControl: options.CongestionControl,
		AuthTimeout:       time.Duration(options.AuthTimeout),
		ZeroRTTHandshake:  options.ZeroRTTHandshake,
		Heartbeat:         time.Duration(options.Heartbeat),
		UDPTimeout:        udpTimeout,
		Handler:           inbound,
	})
	if err != nil {
		return nil, err
	}
	var userList []*inboundUser
	var userNameList []string
	var userUUIDList [][16]byte
	var userPasswordList []string
	users := make(map[string]*inboundUser, len(options.Users))
	for index, user := range options.Users {
		if user.UUID == "" {
			return nil, E.New("missing uuid for user ", index)
		}
		userUUID, err := uuid.FromString(user.UUID)
		if err != nil {
			return nil, E.Cause(err, "invalid uuid for user ", index)
		}
		if _, exists := users[user.UUID]; exists {
			return nil, E.New("duplicate uuid for user ", index)
		}
		identity := &inboundUser{TUICUser: user, id: index}
		users[user.UUID] = identity
		userList = append(userList, identity)
		userNameList = append(userNameList, user.UUID)
		userUUIDList = append(userUUIDList, userUUID)
		userPasswordList = append(userPasswordList, user.Password)
	}
	service.UpdateUsers(userList, userUUIDList, userPasswordList)
	inbound.server = service
	inbound.userNameList = userNameList
	inbound.users = users
	inbound.userconns = sync.Map{}
	return inbound, nil
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	user, _ := auth.UserFromContext[*inboundUser](ctx)
	if userName, found := h.registerUserConnection(user, conn); found {
		onClose = N.AppendClose(onClose, func(err error) {
			h.userconns.Delete(conn)
		})
		if userName != "" {
			metadata.User = userName
			h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
		} else {
			h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
		}
	} else {
		h.logger.WarnContext(ctx, "no valid user for inbound connection to ", metadata.Destination)
		conn.Close()
		return
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	user, _ := auth.UserFromContext[*inboundUser](ctx)
	if userName, found := h.registerUserConnection(user, conn); found {
		onClose = N.AppendClose(onClose, func(err error) {
			h.userconns.Delete(conn)
		})
		if userName != "" {
			metadata.User = userName
			h.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", metadata.Destination)
		} else {
			h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
		}
	} else {
		h.logger.WarnContext(ctx, "no valid user for inbound packet connection to ", metadata.Destination)
		conn.Close()
		return
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
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
	packetConn, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	return h.server.Start(packetConn)
}

func (h *Inbound) Close() error {
	h.usersAccess.Lock()
	h.closed = true
	retired := make(map[*inboundUser]struct{}, len(h.users))
	for _, user := range h.users {
		retired[user] = struct{}{}
	}
	h.users = nil
	h.userNameList = nil
	conns := h.detachUsersLocked(retired)
	h.usersAccess.Unlock()
	closeUserConnections(conns)
	return common.Close(
		h.listener,
		h.tlsConfig,
		common.PtrOrNil(h.server),
	)
}

func (h *Inbound) registerUserConnection(user *inboundUser, conn io.Closer) (string, bool) {
	h.usersAccess.RLock()
	defer h.usersAccess.RUnlock()
	if h.closed || user == nil || h.users[user.UUID] != user {
		return "", false
	}
	h.userconns.Store(conn, user)
	return user.UUID, true
}
