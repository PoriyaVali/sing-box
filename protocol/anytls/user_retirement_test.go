package anytls

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
)

type slowRetirementConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	closed  atomic.Int32
	once    sync.Once
}

func (c *slowRetirementConn) Close() error {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
		c.closed.Add(1)
	})
	return nil
}

func sessionUserContext(h *Inbound, conn net.Conn) context.Context {
	h.usersAccess.RLock()
	session := &inboundSession{users: h.users, conn: conn}
	h.usersAccess.RUnlock()
	return auth.ContextWithUser(context.WithValue(context.Background(), sessionContextKey{}, session), physicalUser)
}

func TestDelUsersSlowPhysicalCloseAllowsFreshGeneration(t *testing.T) {
	h := physicalInbound(t)
	old := &slowRetirementConn{entered: make(chan struct{}), release: make(chan struct{})}
	ctx := sessionUserContext(h, old)
	cleanup, err := h.authenticatedSession(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	deleted := make(chan error, 1)
	go func() { deleted <- h.DelUsers([]string{physicalUser}) }()
	defer func() {
		close(old.release)
		select {
		case err := <-deleted:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("old deletion did not finish")
		}
	}()
	select {
	case <-old.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("physical close did not begin")
	}
	fresh, peer := net.Pipe()
	defer fresh.Close()
	defer peer.Close()
	added := make(chan error, 1)
	go func() {
		if err := h.AddUsers([]option.AnyTLSUser{{Name: physicalUser, Password: physicalPassword}}); err != nil {
			added <- err
			return
		}
		_, err := h.authenticatedSession(sessionUserContext(h, fresh), fresh)
		added <- err
	}()
	select {
	case err := <-added:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow network close blocked membership update")
	}
	if _, err := h.authenticatedSession(ctx, old); err == nil {
		t.Fatal("old authenticated generation accepted after re-add")
	}
	cleanup()
	if _, found := h.userconns.Load(fresh); !found {
		t.Fatal("old session cleanup removed the fresh session")
	}
}

func TestAnyTLSUpdatesPreserveCredentialsAndGeneration(t *testing.T) {
	h := physicalInbound(t)
	old := h.users[physicalUser]
	if err := h.AddUsers([]option.AnyTLSUser{old.AnyTLSUser}); err != nil {
		t.Fatal(err)
	}
	if h.users[physicalUser] != old || len(h.uuidlist) != 1 {
		t.Fatal("unchanged credentials replaced a generation or duplicated its name")
	}
	if err := h.AddUsers([]option.AnyTLSUser{{Name: "other", Password: "other password"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.DelUsers([]string{"other"}); err != nil {
		t.Fatal(err)
	}
	client := physicalClient(t, h)
	writePhysicalAuth(t, client)
	waitPhysicalSessions(t, h, 1)
}
