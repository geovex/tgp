package network_exchange

import (
	"fmt"
	"runtime"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/stats"
	"github.com/geovex/tgp/internal/tgcrypt"
)

func (o *ClientHandler) handleObfClient(initialPacket tgcrypt.Nonce) (err error) {
	if tgcrypt.IsWrongNonce(&initialPacket) {
		return o.handleFallBack(initialPacket[:])
	}
	var user *string
	for name := range o.config.IterateUsers() {
		runtime.Gosched()
		u, err := o.config.GetUser(name)
		if err != nil {
			panic("invalid name in user iteration")
		}
		userSecret, err := tgcrypt.NewSecretHex(u.Secret)
		if err != nil {
			continue
		}
		o.cliCtx, err = tgcrypt.ObfCtxFromNonce(initialPacket, userSecret)
		if err != nil {
			continue
		}
		// basic afterchecks
		if o.cliCtx.Dc > tgcrypt.DcMaxIdx || o.cliCtx.Dc < -tgcrypt.DcMaxIdx || o.cliCtx.Dc == 0 {
			continue
		}
		user = &u.Name
		fmt.Printf("Client connected %s, protocol: %x\n", *user, o.cliCtx.Protocol)
		break
	}
	if user == nil {
		return o.handleFallBack(initialPacket[:])
	}
	o.statsHandle.SetAuthorized(*user)
	//connect to dc
	var u config.User
	u, err = o.config.GetUser(*user)
	if err != nil {
		panic("user found, but GetUser failed")
	}
	o.user = &u
	var flags = stats.ConnectionFlags{
		Obfuscated: true,
	}
	o.statsHandle.OrFlags(flags)
	o.cliStream = newObfuscatedStream(o.client, o.cliCtx, nil, o.cliCtx.Protocol)
	err = o.processWithConfig()
	fmt.Printf("Client disconnected %s\n", o.user.Name)
	return
}
