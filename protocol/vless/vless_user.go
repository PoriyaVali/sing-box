package vless

import (
	"net"

	"github.com/sagernet/sing-box/option"
)

func vlessUserName(u option.VLESSUser) string { return u.Name }

// syncUsersLocked hands the service the current users under their stable
// IDs. Callers hold usersUpdate (or own the inbound, during construction).
func (h *Inbound) syncUsersLocked() {
	ids, users := h.users.Snapshot()
	uuids := make([]string, len(users))
	flows := make([]string, len(users))
	for i, u := range users {
		uuids[i] = u.UUID
		flows[i] = u.Flow
	}
	h.service.UpdateUsers(ids, uuids, flows)
}

func (h *Inbound) AddUsers(users []option.VLESSUser) error {
	h.usersUpdate.Lock()
	defer h.usersUpdate.Unlock()
	h.users.Add(users, vlessUserName)
	h.syncUsersLocked()
	return nil
}

func (h *Inbound) DelUsers(names []string) error {
	for _, name := range names {
		h.userconns.Range(func(key, value interface{}) bool {
			if value.(string) == name {
				key.(net.Conn).Close()
				h.userconns.Delete(key)
			}
			return true
		})
	}
	h.usersUpdate.Lock()
	defer h.usersUpdate.Unlock()
	h.users.Delete(names)
	h.syncUsersLocked()
	return nil
}
