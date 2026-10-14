package anytls

import (
	"net"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-box/option"
)

func (h *Inbound) AddUsers(users []option.AnyTLSUser) error {
	h.usersAccess.Lock()
	if h.closed {
		h.usersAccess.Unlock()
		return net.ErrClosed
	}
	next := make(map[string]*inboundUser, len(h.users)+len(users))
	for name, user := range h.users {
		next[name] = user
	}
	retired := make(map[*inboundUser]struct{})
	for _, user := range users {
		old := next[user.Name]
		if old != nil && old.AnyTLSUser == user {
			continue
		}
		if old == nil {
			h.uuidlist = append(h.uuidlist, user.Name)
		} else {
			retired[old] = struct{}{}
		}
		next[user.Name] = &inboundUser{AnyTLSUser: user}
	}
	h.users = next
	h.updateUsersLocked()
	conns := h.detachUsersLocked(retired)
	h.usersAccess.Unlock()
	closeUserConnections(conns)
	return nil
}

func (h *Inbound) DelUsers(names []string) error {
	if len(names) == 0 {
		return nil
	}

	h.usersAccess.Lock()
	next := make(map[string]*inboundUser, len(h.users))
	for name, user := range h.users {
		next[name] = user
	}
	retired := make(map[*inboundUser]struct{})
	for _, name := range names {
		if user := next[name]; user != nil {
			retired[user] = struct{}{}
			delete(next, name)
		}
	}

	remaining := make([]string, 0, len(h.uuidlist))
	for _, uuid := range h.uuidlist {
		if next[uuid] != nil {
			remaining = append(remaining, uuid)
		}
	}

	h.uuidlist = remaining
	h.users = next
	h.updateUsersLocked()
	conns := h.detachUsersLocked(retired)
	h.usersAccess.Unlock()
	closeUserConnections(conns)
	return nil
}

func (h *Inbound) updateUsersLocked() {
	userList := make([]anytls.User, len(h.uuidlist))
	for i, uuid := range h.uuidlist {
		userList[i] = anytls.User(h.users[uuid].AnyTLSUser)
	}
	h.service.UpdateUsers(userList)
}

func (h *Inbound) detachUsersLocked(users map[*inboundUser]struct{}) []net.Conn {
	var conns []net.Conn
	h.userconns.Range(func(key, value any) bool {
		if _, found := users[value.(*inboundUser)]; found {
			h.userconns.Delete(key)
			conns = append(conns, key.(net.Conn))
		}
		return true
	})
	return conns
}

func closeUserConnections(conns []net.Conn) {
	for _, conn := range conns {
		_ = conn.Close()
	}
}
