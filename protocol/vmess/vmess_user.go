package vmess

import (
	"github.com/sagernet/sing-box/option"
)

func vmessUserName(u option.VMessUser) string { return u.Name }

// syncUsersLocked hands the service the current users under their stable
// IDs. Callers hold usersUpdate (or own the inbound, during construction).
func (h *Inbound) syncUsersLocked() error {
	ids, users := h.users.Snapshot()
	uuids := make([]string, len(users))
	alterIDs := make([]int, len(users))
	for i, u := range users {
		uuids[i] = u.UUID
		alterIDs[i] = u.AlterId
	}
	return h.service.UpdateUsers(ids, uuids, alterIDs)
}

func (h *Inbound) AddUsers(users []option.VMessUser) error {
	h.usersUpdate.Lock()
	defer h.usersUpdate.Unlock()
	h.users.Add(users, vmessUserName)
	return h.syncUsersLocked()
}

func (h *Inbound) DelUsers(uuids []string) error {
	h.usersUpdate.Lock()
	defer h.usersUpdate.Unlock()
	h.users.Delete(uuids)
	return h.syncUsersLocked()
}
