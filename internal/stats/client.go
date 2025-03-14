package stats

import "net"

type ClientState uint8

type ConnectionFlags struct {
	Obfuscated, FakeTls, MiddleProxy bool
}

const (
	None ClientState = iota
	Connected
	Fallback
	Authorized
)

// TODO: use atomics, stats does not need to be precise
type Client struct {
	Name    *string
	cliSock *net.TCPConn
	state   ClientState
	flags   ConnectionFlags
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
	sh.client.Name = &name
	sh.client.state = Authorized
	sh.stats.lock.Unlock()
}

func (sh *StatsHandle) SetConnected(cliSock *net.TCPConn) {
	sh.stats.lock.Lock()
	sh.client.cliSock = cliSock
	sh.client.state = Connected
	sh.stats.lock.Unlock()
}

func (sh *StatsHandle) SetState(state ClientState) {
	sh.stats.lock.Lock()
	sh.client.state = state
	sh.stats.lock.Unlock()
}

func (sh *StatsHandle) OrFlags(flags ConnectionFlags) {
	sh.stats.lock.Lock()
	sh.client.flags.FakeTls = sh.client.flags.FakeTls || flags.FakeTls
	sh.client.flags.Obfuscated = sh.client.flags.Obfuscated || flags.Obfuscated
	sh.client.flags.MiddleProxy = sh.client.flags.MiddleProxy || flags.MiddleProxy
	sh.stats.lock.Unlock()
}

func (sh *StatsHandle) ResetFlags(flags ConnectionFlags) {
	sh.stats.lock.Lock()
	sh.client.flags = ConnectionFlags{
		FakeTls:     false,
		Obfuscated:  false,
		MiddleProxy: false,
	}
	sh.stats.lock.Unlock()
}
