package obfs

import (
	"fmt"
	"net"

	"github.com/icpz/open-snell/components/simple-obfs/http"
	"github.com/icpz/open-snell/components/simple-obfs/tls"
)

func NewObfsServer(conn net.Conn, obfs string) (c net.Conn, err error) {
	switch obfs {
	case "tls":
		c = tls.NewTLSObfsServer(conn)
	case "http":
		c = http.NewHTTPObfsServer(conn)
	case "none", "":
		c = conn
	default:
		c = nil
		err = fmt.Errorf("invalid obfs type %s", obfs)
	}
	return
}

func NewObfsClient(conn net.Conn, server, port, obfs string) (c net.Conn, err error) {
	switch obfs {
	case "tls":
		c = tls.NewTLSObfsClient(conn, server)
	case "http":
		c = http.NewHTTPObfsClient(conn, server, port)
	case "none", "":
		c = conn
	default:
		c = nil
		err = fmt.Errorf("invalid obfs type %s", obfs)
	}
	return
}
