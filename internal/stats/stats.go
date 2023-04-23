package stats

import (
	"fmt"
	"sync"
)

type Stats struct {
	lock    sync.RWMutex
	clients []*Client
}

func New() *Stats {
	return &Stats{
		lock: sync.RWMutex{},
		// TODO: do slab here
		clients: []*Client{},
	}
}

func (s *Stats) AllocClient() *StatsHandle {
	s.lock.Lock()
	defer s.lock.Unlock()
	client := newClient()
	s.clients = append(s.clients, client)
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
	s.lock.RLock()
	defer s.lock.RUnlock()
	return fmt.Sprintf("Clients: %d\n", len(s.clients))
}
