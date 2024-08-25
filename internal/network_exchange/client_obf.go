package network_exchange

import (
	"fmt"
	"runtime"

	"github.com/geovex/tgp/internal/config"
	"github.com/geovex/tgp/internal/tgcrypt_encryption"
)

func (o *ClientHandler) handleObfClient(initialPacket [tgcrypt_encryption.NonceSize]byte) (err error) {
	var user *string
	for u := range o.config.IterateUsers() {
		runtime.Gosched()
		if tgcrypt_encryption.IsWrongNonce(initialPacket) {
			continue
		}
		userSecret, err := tgcrypt_encryption.NewSecretHex(u.Secret)
		if err != nil {
			continue
		}
		o.cliCtx, err = tgcrypt_encryption.ObfCtxFromNonce(initialPacket, userSecret)
		if err != nil {
			continue
		}
		// basic afterchecks
		if o.cliCtx.Dc > tgcrypt_encryption.DcMaxIdx || o.cliCtx.Dc < -tgcrypt_encryption.DcMaxIdx || o.cliCtx.Dc == 0 {
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
	o.cliStream = newObfuscatedStream(o.client, o.cliCtx, nil, o.cliCtx.Protocol)
	err = o.processWithConfig()
	fmt.Printf("Client disconnected %s\n", o.user.Name)
	return
}
