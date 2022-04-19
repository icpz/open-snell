
package snell

import (
	"errors"
	"net"
	"syscall"

	log "github.com/golang/glog"
)

func setTcpFastOpen(lis net.Listener, enable int) error {
	if tl, ok := lis.(*net.TCPListener); ok {
		file, err := tl.File()
		if err != nil {
			return err
		}
		sysconn, err := file.SyscallConn()
		if err != nil {
			return err
		}
		return sysconn.Control(func(fd uintptr) {
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, 23, enable); err != nil {
				log.Warningf("failed to set TCP fastopen: %v\n", err)
			}
		})
	}
	return errors.New("invalid listener")
}
