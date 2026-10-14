package tuic

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	Q "github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type retirementPacketConn struct{ closed atomic.Int32 }

var _ N.PacketConn = (*retirementPacketConn)(nil)

func (c *retirementPacketConn) Close() error { c.closed.Add(1); return nil }
func (*retirementPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, net.ErrClosed
}
func (*retirementPacketConn) WritePacket(*buf.Buffer, M.Socksaddr) error { return net.ErrClosed }
func (*retirementPacketConn) LocalAddr() net.Addr                        { return &net.UDPAddr{} }
func (*retirementPacketConn) SetDeadline(time.Time) error                { return nil }
func (*retirementPacketConn) SetReadDeadline(time.Time) error            { return nil }
func (*retirementPacketConn) SetWriteDeadline(time.Time) error           { return nil }

func TestDelUsersClosesPacketConnection(t *testing.T) {
	h := retirementInbound(t)
	conn := &retirementPacketConn{}
	if _, ok := h.registerUserConnection(h.users[retirementUUID], conn); !ok {
		t.Fatal("registration refused")
	}
	if err := h.DelUsers([]string{retirementUUID}); err != nil {
		t.Fatal(err)
	}
	if conn.closed.Load() != 1 {
		t.Fatalf("packet close count = %d", conn.closed.Load())
	}
}

const retirementUUID = "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"

func retirementInbound(t *testing.T) *Inbound {
	t.Helper()
	service, err := Q.NewService[*inboundUser](Q.ServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := &Inbound{server: service, listener: &listener.Listener{}, users: map[string]*inboundUser{}}
	if err := h.AddUsers([]option.TUICUser{{Name: "display name", UUID: retirementUUID, Password: "different secret"}}, []int{17}); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestDelUsersClosesTCPAndRejectsOldGeneration(t *testing.T) {
	h := retirementInbound(t)
	old := h.users[retirementUUID]
	server, client := net.Pipe()
	defer client.Close()
	if _, ok := h.registerUserConnection(old, server); !ok {
		t.Fatal("registration refused")
	}
	if err := h.DelUsers([]string{retirementUUID}); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("deleted TCP connection remains open")
	}
	if _, ok := h.registerUserConnection(old, &retirementPacketConn{}); ok {
		t.Fatal("removed identity accepted")
	}
	if err := h.AddUsers([]option.TUICUser{old.TUICUser}, []int{old.id}); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.registerUserConnection(old, &retirementPacketConn{}); ok {
		t.Fatal("old QUIC authentication accepted after re-add")
	}
	if _, ok := h.registerUserConnection(h.users[retirementUUID], &retirementPacketConn{}); !ok {
		t.Fatal("fresh generation refused")
	}
}

type retirementSlowPacketConn struct {
	retirementPacketConn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *retirementSlowPacketConn) Close() error {
	c.once.Do(func() { close(c.entered); <-c.release; c.closed.Add(1) })
	return nil
}

func TestDelUsersSlowCloseAllowsFreshGeneration(t *testing.T) {
	h := retirementInbound(t)
	old := h.users[retirementUUID]
	conn := &retirementSlowPacketConn{entered: make(chan struct{}), release: make(chan struct{})}
	h.registerUserConnection(old, conn)
	deleted := make(chan error, 1)
	go func() { deleted <- h.DelUsers([]string{retirementUUID}) }()
	defer func() {
		close(conn.release)
		select {
		case err := <-deleted:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("old deletion did not finish")
		}
	}()
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("close did not begin")
	}
	fresh := &retirementPacketConn{}
	added := make(chan error, 1)
	go func() {
		if err := h.AddUsers([]option.TUICUser{old.TUICUser}, []int{old.id}); err != nil {
			added <- err
			return
		}
		h.usersAccess.RLock()
		identity := h.users[retirementUUID]
		h.usersAccess.RUnlock()
		_, accepted := h.registerUserConnection(identity, fresh)
		if !accepted {
			t.Error("fresh generation refused")
		}
		added <- nil
	}()
	select {
	case err := <-added:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow network close held membership lock")
	}
	if fresh.closed.Load() != 0 {
		t.Fatal("old deletion closed fresh connection")
	}
}

func TestTUICPreservesUUIDMetadataAndCredentials(t *testing.T) {
	h := retirementInbound(t)
	old := h.users[retirementUUID]
	conn := &retirementPacketConn{}
	if name, ok := h.registerUserConnection(old, conn); !ok || name != retirementUUID {
		t.Fatalf("routing identity = %q, accepted = %v; want panel UUID", name, ok)
	}
	if old.Password != "different secret" || old.id != 17 {
		t.Fatal("panel credentials or numeric identity were lost")
	}
	if err := h.AddUsers([]option.TUICUser{old.TUICUser}, []int{old.id}); err != nil {
		t.Fatal(err)
	}
	if h.users[retirementUUID] != old || len(h.userNameList) != 1 || conn.closed.Load() != 0 {
		t.Fatal("unchanged update retired an active generation")
	}
	changed := old.TUICUser
	changed.Password = "replacement secret"
	if err := h.AddUsers([]option.TUICUser{changed}, []int{old.id}); err != nil {
		t.Fatal(err)
	}
	if conn.closed.Load() != 1 {
		t.Fatal("credential replacement did not close the old connection")
	}
	if _, ok := h.registerUserConnection(old, &retirementPacketConn{}); ok {
		t.Fatal("replaced credentials still authorize an old QUIC session")
	}
}

func TestTUICCloseRevokesActiveAndFutureConnections(t *testing.T) {
	h := retirementInbound(t)
	old := h.users[retirementUUID]
	conn := &retirementPacketConn{}
	h.registerUserConnection(old, conn)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.closed.Load() != 1 {
		t.Fatal("inbound close left a packet connection open")
	}
	if _, ok := h.registerUserConnection(old, &retirementPacketConn{}); ok {
		t.Fatal("closed inbound accepted an old authenticated session")
	}
	if err := h.AddUsers([]option.TUICUser{old.TUICUser}, []int{old.id}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("add after close = %v, want net.ErrClosed", err)
	}
}

func TestAddUsersInvalidBatchIsAtomic(t *testing.T) {
	h := retirementInbound(t)
	old := h.users[retirementUUID]
	valid := option.TUICUser{Name: "valid", UUID: "7ffb0947-3596-44c7-8f8e-fb89e5087cba", Password: "secret"}
	if err := h.AddUsers([]option.TUICUser{valid, {UUID: "invalid"}}, []int{18, 19}); err == nil {
		t.Fatal("invalid batch accepted")
	}
	if len(h.users) != 1 || h.users[retirementUUID] != old {
		t.Fatal("invalid batch modified active users")
	}
	if err := h.AddUsers([]option.TUICUser{valid}, nil); err == nil {
		t.Fatal("mismatched ID counts accepted")
	}
}

func TestUserRegistrationDuringUpdates(t *testing.T) {
	h := retirementInbound(t)
	user := h.users[retirementUUID].TUICUser
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			h.DelUsers([]string{retirementUUID})
			if err := h.AddUsers([]option.TUICUser{user}, []int{17}); err != nil {
				t.Error(err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 5000; i++ {
			h.usersAccess.RLock()
			identity := h.users[retirementUUID]
			h.usersAccess.RUnlock()
			conn := &retirementPacketConn{}
			h.registerUserConnection(identity, conn)
			h.userconns.Delete(conn)
		}
	}()
	wg.Wait()
}
