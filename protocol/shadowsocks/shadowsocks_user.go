package shadowsocks

import (
	"github.com/sagernet/sing-box/option"
)

func shadowsocksUserName(u option.ShadowsocksUser) string { return u.Name }

// syncUsersLocked hands the service the current users under their stable
// IDs. Callers hold usersUpdate (or own the inbound, during construction).
func (h *MultiInbound) syncUsersLocked() error {
	ids, users := h.users.Snapshot()
	passwords := make([]string, len(users))
	for i, u := range users {
		passwords[i] = u.Password
	}
	return h.service.UpdateUsersWithPasswords(ids, passwords)
}

func (h *MultiInbound) AddUsers(users []option.ShadowsocksUser) error {
	h.usersUpdate.Lock()
	defer h.usersUpdate.Unlock()
	h.users.Add(users, shadowsocksUserName)
	return h.syncUsersLocked()
}

func (h *MultiInbound) DelUsers(names []string) error {
	h.usersUpdate.Lock()
	defer h.usersUpdate.Unlock()
	h.users.Delete(names)
	return h.syncUsersLocked()
}
