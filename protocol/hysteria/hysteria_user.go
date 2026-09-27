package hysteria

import "github.com/sagernet/sing-box/option"

func hysteriaUserName(u option.HysteriaUser) string { return u.Name }

func hysteriaPassword(u option.HysteriaUser) string {
	if u.AuthString != "" {
		return u.AuthString
	}
	return string(u.Auth)
}

// syncUsersLocked hands the service the current users under their stable
// IDs. Callers hold usersUpdate (or own the inbound, during construction).
func (h *Inbound) syncUsersLocked() {
	ids, users := h.users.Snapshot()
	passwords := make([]string, len(users))
	for i, u := range users {
		passwords[i] = hysteriaPassword(u)
	}
	h.service.UpdateUsers(ids, passwords)
}

func (h *Inbound) AddUsers(users []option.HysteriaUser) error {
	h.usersUpdate.Lock()
	defer h.usersUpdate.Unlock()
	h.users.Add(users, hysteriaUserName)
	h.syncUsersLocked()
	return nil
}

func (h *Inbound) DelUsers(names []string) error {
	if len(names) == 0 {
		return nil
	}
	h.usersUpdate.Lock()
	defer h.usersUpdate.Unlock()
	h.users.Delete(names)
	h.syncUsersLocked()
	return nil
}
