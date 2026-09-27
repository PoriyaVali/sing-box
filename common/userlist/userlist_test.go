package userlist

import (
	"strconv"
	"sync"
	"testing"
)

type user struct{ name, pass string }

func nameOf(u user) string { return u.name }

// A removal must not move anyone else: IDs are for keeps.
func TestIDsSurviveRemovals(t *testing.T) {
	l := New[user]()
	l.Add([]user{{"a", "1"}, {"b", "2"}, {"c", "3"}}, nameOf)
	ids, users := l.Snapshot()
	idOf := map[string]int{}
	for i, u := range users {
		idOf[u.name] = ids[i]
	}
	l.Delete([]string{"a"})
	if n, ok := l.Name(idOf["c"]); !ok || n != "c" {
		t.Fatalf("c resolves to %q (%v) after a removal", n, ok)
	}
	if _, ok := l.Name(idOf["a"]); ok {
		t.Fatal("a removed user still resolves")
	}
	l.Add([]user{{"d", "4"}}, nameOf)
	if n, _ := l.Name(idOf["a"]); n == "d" {
		t.Fatal("a new user reused a removed user's ID")
	}
}

func TestReAddKeepsID(t *testing.T) {
	l := New[user]()
	l.Add([]user{{"a", "1"}}, nameOf)
	ids, _ := l.Snapshot()
	l.Add([]user{{"a", "new-pass"}}, nameOf)
	ids2, users := l.Snapshot()
	if len(ids2) != 1 || ids2[0] != ids[0] || users[0].pass != "new-pass" {
		t.Fatalf("re-adding a user: ids %v -> %v, users %v", ids, ids2, users)
	}
}

func TestUnnamedUsersAreDistinct(t *testing.T) {
	l := New[user]()
	l.Add([]user{{"", "x"}, {"", "y"}}, nameOf)
	if l.Len() != 2 {
		t.Fatalf("len = %d, want 2", l.Len())
	}
}

func TestReplace(t *testing.T) {
	l := New[user]()
	l.Add([]user{{"a", "1"}, {"b", "2"}}, nameOf)
	ids, users := l.Snapshot()
	var idB int
	for i, u := range users {
		if u.name == "b" {
			idB = ids[i]
		}
	}
	l.Replace([]user{{"b", "2"}, {"c", "3"}}, nameOf)
	if l.Len() != 2 {
		t.Fatalf("len = %d, want 2", l.Len())
	}
	if n, ok := l.Name(idB); !ok || n != "b" {
		t.Fatal("a user kept by Replace lost its ID")
	}
}

// Lookups while users change - what connections do during a panel sync.
func TestConcurrentLookupsAndChanges(t *testing.T) {
	l := New[user]()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				l.Name(i % 100)
				l.Snapshot()
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		n := strconv.Itoa(i)
		l.Add([]user{{n, n}}, nameOf)
		if i%3 == 0 {
			l.Delete([]string{strconv.Itoa(i / 2)})
		}
	}
	close(stop)
	wg.Wait()
}
