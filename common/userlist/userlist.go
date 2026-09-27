// Package userlist keeps the users an inbound serves under IDs that stay
// the same while it runs.
//
// The multi-user inbounds used to hand their protocol service the position
// of each user in a slice as its ID, and resolve an authenticated connection
// back to a name by indexing that slice. Users are added and removed while
// the inbound serves connections (a panel sync), and the slice was replaced
// under them with no lock: a removal shifted every later user down, so a
// connection that authenticated just before it was billed to someone else -
// or indexed past the end of the shorter slice and panicked, taking the whole
// process down. The inbounds that kept a map instead read it while it was
// written, which Go ends with a fatal error.
//
// An ID here belongs to one user for as long as the list exists, and lookups
// are safe against concurrent changes.
package userlist

import "sync"

// List is safe for concurrent use.
type List[T any] struct {
	access sync.RWMutex
	nextID int
	byName map[string]int // name -> ID, for users that have a name
	byID   map[int]entry[T]
}

type entry[T any] struct {
	name string
	user T
}

func New[T any]() *List[T] {
	return &List[T]{byName: map[string]int{}, byID: map[int]entry[T]{}}
}

// Add registers each user under name(user) and returns nothing new for a
// name already present: that user is updated in place and keeps its ID.
// Users without a name each get their own ID.
func (l *List[T]) Add(users []T, name func(T) string) {
	l.access.Lock()
	defer l.access.Unlock()
	for _, u := range users {
		n := name(u)
		if id, ok := l.byName[n]; ok && n != "" {
			l.byID[id] = entry[T]{name: n, user: u}
			continue
		}
		id := l.nextID
		l.nextID++
		l.byID[id] = entry[T]{name: n, user: u}
		if n != "" {
			l.byName[n] = id
		}
	}
}

// Delete removes the named users.
func (l *List[T]) Delete(names []string) {
	l.access.Lock()
	defer l.access.Unlock()
	for _, n := range names {
		if id, ok := l.byName[n]; ok {
			delete(l.byName, n)
			delete(l.byID, id)
		}
	}
}

// Replace makes the list exactly users. Users whose name is already listed
// keep their ID.
func (l *List[T]) Replace(users []T, name func(T) string) {
	keep := make(map[string]struct{}, len(users))
	for _, u := range users {
		keep[name(u)] = struct{}{}
	}
	l.access.Lock()
	for id, e := range l.byID {
		if _, ok := keep[e.name]; !ok || e.name == "" {
			delete(l.byID, id)
			if e.name != "" {
				delete(l.byName, e.name)
			}
		}
	}
	l.access.Unlock()
	l.Add(users, name)
}

// Name returns the name of the user with this ID, and whether that user is
// still listed.
func (l *List[T]) Name(id int) (string, bool) {
	l.access.RLock()
	defer l.access.RUnlock()
	e, ok := l.byID[id]
	return e.name, ok
}

// Snapshot returns every user with its ID, in no particular order - what a
// protocol service's UpdateUsers takes.
func (l *List[T]) Snapshot() (ids []int, users []T) {
	l.access.RLock()
	defer l.access.RUnlock()
	ids = make([]int, 0, len(l.byID))
	users = make([]T, 0, len(l.byID))
	for id, e := range l.byID {
		ids = append(ids, id)
		users = append(users, e.user)
	}
	return ids, users
}

// Len is the number of users listed.
func (l *List[T]) Len() int {
	l.access.RLock()
	defer l.access.RUnlock()
	return len(l.byID)
}
