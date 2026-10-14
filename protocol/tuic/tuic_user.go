package tuic

import (
	"io"
	"net"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func (h *Inbound) AddUsers(users []option.TUICUser, ids []int) error {
	if len(users) != len(ids) {
		return E.New("TUIC user and ID counts differ")
	}
	seen := make(map[string]struct{}, len(users))
	for i, user := range users {
		if _, err := uuid.FromString(user.UUID); err != nil {
			return E.Cause(err, "invalid uuid for user ", i)
		}
		if _, exists := seen[user.UUID]; exists {
			return E.New("duplicate uuid for user ", i)
		}
		seen[user.UUID] = struct{}{}
	}
	h.usersAccess.Lock()
	if h.closed {
		h.usersAccess.Unlock()
		return net.ErrClosed
	}
	if h.users == nil {
		h.users = make(map[string]*inboundUser)
	}
	retired := make(map[*inboundUser]struct{})
	for i, user := range users {
		old := h.users[user.UUID]
		if old != nil && old.TUICUser == user && old.id == ids[i] {
			continue
		}
		if old == nil {
			h.userNameList = append(h.userNameList, user.UUID)
		} else {
			retired[old] = struct{}{}
		}
		h.users[user.UUID] = &inboundUser{TUICUser: user, id: ids[i]}
	}
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
	retired := make(map[*inboundUser]struct{})
	for _, name := range names {
		if user := h.users[name]; user != nil {
			retired[user] = struct{}{}
			delete(h.users, name)
		}
	}
	remaining := make([]string, 0, len(h.userNameList))
	for _, uuid := range h.userNameList {
		if h.users[uuid] != nil {
			remaining = append(remaining, uuid)
		}
	}
	h.userNameList = remaining
	h.updateUsersLocked()
	conns := h.detachUsersLocked(retired)
	h.usersAccess.Unlock()
	// Both TCP and packet connections implement io.Closer. Never run network
	// I/O while holding membership locks or re-read the live set after unlock.
	closeUserConnections(conns)
	return nil
}

func (h *Inbound) updateUsersLocked() {
	users := make([]*inboundUser, 0, len(h.userNameList))
	uuids := make([][16]byte, 0, len(h.userNameList))
	passwords := make([]string, 0, len(h.userNameList))
	for _, uuidString := range h.userNameList {
		user := h.users[uuidString]
		users = append(users, user)
		uuids = append(uuids, uuid.Must(uuid.FromString(user.UUID)))
		passwords = append(passwords, user.Password)
	}
	h.server.UpdateUsers(users, uuids, passwords)
}

func (h *Inbound) detachUsersLocked(users map[*inboundUser]struct{}) []io.Closer {
	var conns []io.Closer
	h.userconns.Range(func(key, value any) bool {
		if _, found := users[value.(*inboundUser)]; found {
			h.userconns.Delete(key)
			conns = append(conns, key.(io.Closer))
		}
		return true
	})
	return conns
}

func closeUserConnections(conns []io.Closer) {
	for _, conn := range conns {
		_ = conn.Close()
	}
}
