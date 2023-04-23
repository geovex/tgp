package obfuscated

import (
	"fmt"
	"runtime"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/tgcrypt"
)

func (o *ClientHandler) handleObfClient(initialPacket [tgcrypt.NonceSize]byte) (err error) {
	var user *string
	for u := range o.config.IterateUsers() {
		runtime.Gosched()
		if tgcrypt.IsWrongNonce(initialPacket) {
			continue
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
		if o.cliCtx.Dc > dcMaxIdx || o.cliCtx.Dc < -dcMaxIdx || o.cliCtx.Dc == 0 {
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
	o.user = &u
	if err != nil {
		panic("user found, but GetUser not")
	}
	o.cliStream = newObfuscatedStream(o.client, o.cliCtx, nil, o.cliCtx.Protocol)
	err = o.processWithConfig()
	fmt.Printf("Client disconnected %s\n", o.user.Name)
	return
}
