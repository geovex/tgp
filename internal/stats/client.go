package stats

import "net"

type ClientState uint8

const (
	None ClientState = iota
	Connected
	Fallback
	Authorized
	Simple
	Obfuscated
	Middleproxy
)

type Client struct {
	Name    *string
	cliSock *net.TCPConn
	state   ClientState
}

type StatsHandle struct {
	stats  *Stats
	client *Client
}

func newClient() *Client {
	return &Client{
		state: None,
	}
}

func (sh *StatsHandle) Close() {
	sh.stats.removeClient(sh.client)
}

func (sh *StatsHandle) SetAuthorized(name string) {
	sh.stats.lock.Lock()
	defer sh.stats.lock.Unlock()
	sh.client.Name = &name
	sh.client.state = Authorized
}

func (sh *StatsHandle) SetConnected(cliSock *net.TCPConn) {
	sh.stats.lock.Lock()
	defer sh.stats.lock.Unlock()
	sh.client.cliSock = cliSock
	sh.client.state = Connected
}

func (sh *StatsHandle) SetState(state ClientState) {
	sh.stats.lock.Lock()
	defer sh.stats.lock.Unlock()
	sh.client.state = state
}
