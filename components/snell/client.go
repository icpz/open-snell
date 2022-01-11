/*
 * This file is part of open-snell.
 * open-snell is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * open-snell is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with open-snell.  If not, see <https://www.gnu.org/licenses/>.
 */

package snell

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	log "github.com/golang/glog"

	"github.com/icpz/open-snell/components/aead"
	obfs "github.com/icpz/open-snell/components/simple-obfs"
	"github.com/icpz/open-snell/components/socks5"
	"github.com/icpz/open-snell/components/utils"
	p "github.com/icpz/open-snell/components/utils/pool"
)

const (
	MaxPoolCap    = 10
	PoolTimeoutMS = 150000
)

var (
	bufferPool = sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}
)

type clientSession struct {
	net.Conn
	buffer [1]byte
	reply  bool
}

func (s *clientSession) Read(b []byte) (int, error) {
	if s.reply {
		return s.Conn.Read(b)
	}

	s.reply = true
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return 0, err
	}

	if s.buffer[0] == ResponseTunnel {
		return s.Conn.Read(b)
	} else if s.buffer[0] != ResponseError {
		return 0, errors.New("Command not support")
	}

	// ResponseError
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return 0, err
	}

	length := int(s.buffer[0])
	msg := make([]byte, length)

	if _, err := io.ReadFull(s.Conn, msg); err != nil {
		return 0, err
	}

	return 0, NewAppError(0, string(msg))
}

func WriteHeader(conn net.Conn, host string, port uint, v2 bool) error {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)
	buf.WriteByte(Version)
	if v2 {
		buf.WriteByte(CommandConnectV2)
	} else {
		buf.WriteByte(CommandConnect)
	}

	// clientID length & id
	buf.WriteByte(0)

	// host & port
	buf.WriteByte(uint8(len(host)))
	buf.WriteString(host)
	binary.Write(buf, binary.BigEndian, uint16(port))

	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

type SnellClient struct {
	server   string
	obfs     string
	obfsHost string
	cipher   aead.Cipher
	socks5   *socks5.SockListener
	isV2     bool
	pool     *snellPool
}

func (s *SnellClient) StreamConn(c net.Conn, target string) (net.Conn, error) {
	host, port, _ := net.SplitHostPort(target)
	iport, _ := strconv.Atoi(port)
	err := WriteHeader(c, host, uint(iport), s.isV2)
	return c, err
}

func (s *SnellClient) newSession() (net.Conn, error) {
	c, err := net.Dial("tcp", s.server)
	if err != nil {
		return nil, err
	}

	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
	}

	_, port, _ := net.SplitHostPort(s.server)
	c, _ = obfs.NewObfsClient(c, s.obfsHost, port, s.obfs)

	c = &clientSession{
		Conn: aead.NewConn(c, s.cipher),
	}

	return c, nil
}

func (s *SnellClient) GetSession(target string) (net.Conn, error) {
	c, err := s.pool.Get()
	if err != nil {
		return nil, err
	}
	log.V(1).Infof("Using conn %s\n", c.LocalAddr().String())
	c, err = s.StreamConn(c, target)
	if err != nil {
		s.DropSession(c)
		return nil, err
	}
	return c, nil
}

func (s *SnellClient) PutSession(c net.Conn) {
	if pc, ok := c.(*snellPoolConn); ok {
		pc.Conn.(*clientSession).reply = false
	} else {
		log.Fatalf("Invalid session type!")
	}

	if !s.isV2 {
		s.DropSession(c)
	} else {
		log.V(1).Infof("Cache conn %s\n", c.LocalAddr().String())
		c.Close()
	}
}

func (s *SnellClient) DropSession(c net.Conn) {
	if sess, ok := c.(*snellPoolConn); ok {
		sess.MarkUnusable()
		sess.Close()
	} else {
		log.Fatalf("Invalid session type!")
	}
}

func (s *SnellClient) Close() {
	s.socks5.Close()
	s.pool.Close()
}

func NewSnellClient(listen, server, obfs, obfsHost, psk string, isV2 bool) (*SnellClient, error) {
	if obfs != "tls" && obfs != "http" && obfs != "" {
		return nil, fmt.Errorf("invalid snell obfs type %s", obfs)
	}

	if obfsHost == "" {
		obfsHost = "www.bing.com"
	}

	var cipher aead.Cipher = nil
	if isV2 {
		cipher = aead.NewAES128GCM([]byte(psk))
	} else {
		cipher = aead.NewChacha20Poly1305([]byte(psk))
	}
	sc := &SnellClient{
		server:   server,
		obfs:     obfs,
		obfsHost: obfsHost,
		cipher:   cipher,
		isV2:     isV2,
	}

	p, err := newSnellPool(MaxPoolCap, PoolTimeoutMS, sc.newSession)
	if err != nil {
		return nil, err
	}
	sc.pool = p

	sl, err := socks5.NewSocksProxy(listen, sc.handleSnell)
	if err != nil {
		return nil, err
	}
	sc.socks5 = sl

	return sc, nil
}

func (s *SnellClient) handleSnell(client net.Conn, addr socks5.Addr) {
	target, err := s.GetSession(addr.String())
	log.V(1).Infof("New target from %s to %s\n", client.RemoteAddr().String(), addr.String())
	if err != nil {
		log.Warningf("Failed to connect to target %s, error %v\n", addr.String(), err)
		client.Close()
		return
	}

	_, er := utils.Relay(client, target)

	client.Close()
	if s.isV2 {
		target.SetReadDeadline(time.Time{})
		_, err := target.Write([]byte{}) // write zero chunk back
		if err != nil {
			log.Errorf("Unexpected write error %v\n", err)
			s.DropSession(target)
			return
		}
		switch e := er.(type) {
		case *net.OpError:
			if e.Op == "write" {
				log.V(1).Infof("Ignored write error %v\n", e)
				er = nil
			} else if ae, ok := e.Unwrap().(*AppError); ok {
				log.Errorf("Server reported error: %v\n", ae)
				er = nil
			}
		}
		buf := p.Get(p.RelayBufferSize)
		for er == nil {
			_, err := target.Read(buf)
			er = err
		}
		p.Put(buf)
		if !errors.Is(er, aead.ErrZeroChunk) {
			log.Warningf("Unexpected error %v, ZERO CHUNK wanted\n", er)
			s.DropSession(target)
			return
		}
	}
	s.PutSession(target)

	log.V(1).Infof("Session from %s done\n", client.RemoteAddr().String())
}
