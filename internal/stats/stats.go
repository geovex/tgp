package stats

import (
	"fmt"
	"strings"
	"sync"
)

type Stats struct {
	lock    sync.RWMutex
	clients []*Client
}

func New() *Stats {
	return &Stats{
		lock:    sync.RWMutex{},
		clients: []*Client{},
	}
}

func (s *Stats) AllocClient() *StatsHandle {
	client := newClient()
	s.lock.Lock()
	s.clients = append(s.clients, client)
	s.lock.Unlock()
	clientHandle := &StatsHandle{
		client: client,
		stats:  s,
	}
	return clientHandle
}

func (s *Stats) removeClient(client *Client) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for i, c := range s.clients {
		if c == client {
			s.clients = append(s.clients[:i], s.clients[i+1:]...)
			break
		}
	}
}

func (s *Stats) AsString() string {
	userStats := map[string]int{}
	fallbacks := 0
	// generate per-user stats
	s.lock.RLock()
	for _, c := range s.clients {
		if c.Name != nil && *c.Name != "" {
			userStats[*c.Name]++
		} else if c.state == Fallback {
			fallbacks++
		}
	}
	s.lock.RUnlock()
	b := &strings.Builder{}
	fmt.Fprintf(b, "Clients:\nTotal: %d\n\n", len(s.clients))
	for name, count := range userStats {
		fmt.Fprintf(b, "%s: %d\n", name, count)
	}
	fmt.Fprintf(b, "\nfallbacks: %d\n", fallbacks)
	return b.String()
}
