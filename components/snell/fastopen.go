//go:build !linux

package snell

import (
	"net"
)

func setTcpFastOpen(lis net.Listener, enable int) error {
	return nil
}
