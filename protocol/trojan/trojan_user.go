package trojan

import (
	"net"

	"github.com/sagernet/sing-box/option"
)

func trojanUserName(u option.TrojanUser) string { return u.Name }

// syncUsersLocked hands the service the current users under their stable
// IDs. Callers hold usersUpdate (or own the inbound, during construction).
func (h *Inbound) syncUsersLocked() error {
	ids, users := h.users.Snapshot()
	passwords := make([]string, len(users))
	for i, u := range users {
		passwords[i] = u.Password
	}
	return h.service.UpdateUsers(ids, passwords)
}

func (h *Inbound) AddUsers(users []option.TrojanUser) error {
	h.usersUpdate.Lock()
	defer h.usersUpdate.Unlock()
	h.users.Add(users, trojanUserName)
	return h.syncUsersLocked()
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
	return h.syncUsersLocked()
}
