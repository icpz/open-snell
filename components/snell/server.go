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
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	log "github.com/golang/glog"
	lru "github.com/hashicorp/golang-lru"

	"github.com/icpz/open-snell/components/aead"
	obfs "github.com/icpz/open-snell/components/simple-obfs"
	"github.com/icpz/open-snell/components/utils"
	p "github.com/icpz/open-snell/components/utils/pool"
)

type SnellServer struct {
	listener net.Listener
	psk      []byte
	closed   bool
}

func (s *SnellServer) ServerHandshake(c net.Conn) (target string, cmd byte, err error) {
	buf := make([]byte, 255)
	if _, err = io.ReadFull(c, buf[:3]); err != nil {
		return
	}

	if buf[0] != Version {
		log.Warningf("invalid snell version %x\n", buf[0])
		return
	}

	cmd = buf[1]
	clen := buf[2]
	if clen > 0 {
		if _, err = io.ReadFull(c, buf[:clen]); err != nil {
			return
		}

		log.V(1).Infof("client id %s\n", string(buf[:clen]))
	}

	if cmd == CommandUDP {
		log.V(1).Infof("UDP request, skip reading in handshake stage\n")
		return
	}

	if _, err = io.ReadFull(c, buf[:1]); err != nil {
		return
	}
	hlen := buf[0]
	if _, err = io.ReadFull(c, buf[:hlen+2]); err != nil {
		return
	}
	host := string(buf[:hlen])
	port := strconv.Itoa((int(buf[hlen]) << 8) | int(buf[hlen+1]))
	target = net.JoinHostPort(host, port)
	return
}

func (s *SnellServer) Close() {
	s.closed = true
	s.listener.Close()
}

func NewSnellServer(listen, psk, obfsType string) (*SnellServer, error) {
	if obfsType != "tls" && obfsType != "http" && obfsType != "" {
		return nil, fmt.Errorf("invalid snell obfs type %s", obfsType)
	}

	l, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	setTcpFastOpen(l, 1)

	bpsk := []byte(psk)
	ss := &SnellServer{l, bpsk, false}
	ciph := aead.NewAES128GCM(bpsk)
	fb := aead.NewChacha20Poly1305(bpsk)
	go func() {
		log.Infof("snell server listening at: %s\n", listen)
		for {
			c, err := l.Accept()
			if err != nil {
				if ss.closed {
					break
				}
				continue
			}
			c, _ = obfs.NewObfsServer(c, obfsType)
			c = aead.NewConnWithFallback(c, ciph, fb)
			go ss.handleSnell(c)
		}
	}()

	return ss, nil
}

func (s *SnellServer) handleSnell(conn net.Conn) {
	defer conn.Close()

	isV2 := true

muxLoop:
	for isV2 {
		target, command, err := s.ServerHandshake(conn)
		if err != nil {
			if err != io.EOF {
				log.Warningf("Failed to handshake from %s: %v\n", conn.RemoteAddr().String(), err)
			}
			break
		}

		if command != CommandUDP {
			log.V(1).Infof("New target from %s to %s\n", conn.RemoteAddr().String(), target)
		}

		if c, ok := conn.(*net.TCPConn); ok {
			c.SetKeepAlive(true)
		}

		if command == CommandPing {
			buf := []byte{ResponsePong}
			conn.Write(buf)
			break
		}

		switch command {
		case CommandConnect:
			isV2 = false
		case CommandUDP:
			s.handleUDPRequest(conn)
			break muxLoop
		case CommandConnectV2:
		default:
			log.Errorf("Unknown command 0x%x\n", command)
			break muxLoop
		}

		var el error = nil
		tc, err := net.Dial("tcp", target)
		if err != nil {
			el = s.writeError(conn, err)
		} else {
			defer tc.Close()
			_, el = conn.Write([]byte{ResponseTunnel})
			if el != nil {
				log.Errorf("Failed to write ResponseTunnel: %v\n", el)
			} else {
				el, _ = utils.Relay(conn, tc)
			}
		}

		if isV2 {
			conn.SetReadDeadline(time.Time{})
			_, err := conn.Write([]byte{}) // write zero chunk back
			if err != nil {
				log.Errorf("Unexpected write error %v\n", err)
				return
			}
			if e, ok := el.(*net.OpError); ok {
				if e.Op == "write" {
					el = nil
				}
			}
			buf := p.Get(p.RelayBufferSize)
			for el == nil {
				_, err := conn.Read(buf)
				el = err
			}
			p.Put(buf)
			if !errors.Is(el, aead.ErrZeroChunk) {
				if !errors.Is(el, io.EOF) {
					log.Warningf("Unexpected error %v, ZERO CHUNK wanted\n", el)
				}
				log.V(1).Infof("Close connection due to %v anyway\n", el)
				break
			}
		}
	}

	log.V(1).Infof("Session from %s done", conn.RemoteAddr().String())
}

func (s *SnellServer) writeError(conn net.Conn, err error) error {
	buf := bytes.NewBuffer([]byte{})
	buf.WriteByte(ResponseError)
	if e, ok := err.(syscall.Errno); ok {
		buf.WriteByte(byte(e))
	} else {
		buf.WriteByte(byte(0))
	}
	es := err.Error()
	if len(es) > 250 {
		es = es[0:250]
	}
	buf.WriteByte(byte(len(es)))
	buf.WriteString(es)
	_, el := conn.Write(buf.Bytes())
	return el
}

func (s *SnellServer) handleUDPRequest(conn net.Conn) {
	log.V(1).Infof("New UDP request from %s\n", conn.RemoteAddr().String())

	cache, err := lru.New(256)
	if err != nil {
		log.Errorf("UDP failed to create lru cache: %v\n", err)
		return
	}
	defer cache.Purge()

	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		log.Errorf("UDP failed to listen: %v\n", err)
		s.writeError(conn, err)
		return
	} else {
		defer pc.Close()
		log.V(1).Infof("UDP listening on: %s\n", pc.LocalAddr().String())
		if _, err := conn.Write([]byte{ResponseReady}); err != nil {
			log.Errorf("Failed to write ResponseReady: %v\n", err)
			return
		}
	}

	go s.handleUDPIngress(conn, pc)

	buf := p.Get(p.RelayBufferSize)
	defer p.Put(buf)

uotLoop:
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.V(1).Infof("UDP over TCP read EOF, session ends\n")
			} else {
				log.Errorf("UDP over TCP read error: %v\n", err)
			}
			break
		}

		if n < 5 {
			log.Errorf("UDP over TCP insufficient chunk size: %d < 5\n", n)
			break
		}
		cmd := buf[0]
		hlen := buf[1]
		iplen := 0
		head := 2
		host := ""

		if cmd != CommandUDPForward {
			log.Errorf("UDP over TCP unknown UDP command: 0x%x\n", cmd)
			break
		}
		if hlen == 0 {
			switch buf[2] {
			case 4:
				iplen = 4
			case 6:
				iplen = 16
			default:
				log.Errorf("Unknown IP Version: 0x%x\n", buf[2])
				break uotLoop
			}

			head = 3 + iplen /* now points to port */
			if n < head + 2 {
				log.Errorf("UDP over TCP insufficient chunk size: %d < %d\n", n, head + 2)
				break
			}
			ip := net.IP(buf[3:head])
			host = ip.String()
		} else {
			head = 2 + int(hlen)
			if n < head + 2 {
				log.Errorf("UDP over TCP insufficient chunk size: %d < %d\n", n, head + 2)
				break
			}
			host = string(buf[2:head])
		}
		port := (int(buf[head]) << 8) | int(buf[head+1])
		head += 2
		target := net.JoinHostPort(host, strconv.Itoa(port))
		log.V(1).Infof("UDP over TCP forwarding to %s\n", target)

		var uaddr *net.UDPAddr
		if value, ok := cache.Get(target); ok {
			uaddr = value.(*net.UDPAddr)
			log.V(1).Infof("UDP cache hit: %s -> %s\n", target, uaddr.String())
		} else {
			uaddr, err = net.ResolveUDPAddr("udp", target)
			if err != nil {
				log.Warningf("UDP over TCP failed to resolve %s: %v\n", target, err)
				/* won't close connection, but cause this packet losses */
			}
			log.V(1).Infof("UDP over TCP resolved target %s -> %s\n", target, uaddr.String())
			cache.Add(target, uaddr)
		}

		payloadSize := n - head
		if payloadSize > 0 {
			log.V(1).Infof("UDP over TCP forward %d bytes to target %s\n", payloadSize, target)
			_, err = pc.WriteTo(buf[head:n], uaddr)
			if err != nil {
				log.Errorf("UDP over TCP  failed to write to %s: %v\n", target, err)
				break
			}
		}
	}
}

func (s *SnellServer) handleUDPIngress(conn net.Conn, pc net.PacketConn) {
	buf := p.Get(p.RelayBufferSize)
	defer p.Put(buf)

	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Errorf("UDP failed to read: %v\n", err)
			}
			break
		}
		log.V(1).Infof("UDP read %d bytes from %s\n", n, raddr.String())

		uaddr := raddr.(*net.UDPAddr)
		ipver := 4
		if uaddr.IP.To4() == nil {
			ipver = 6
		}
		buffer := bytes.NewBuffer([]byte{})
		buffer.WriteByte(byte(ipver))
		switch ipver {
		case 4:
			buffer.Write([]byte(uaddr.IP.To4()))
		case 6:
			buffer.Write([]byte(uaddr.IP.To16()))
		}
		buffer.Write([]byte{byte(uaddr.Port>>8), byte(uaddr.Port&0xff)})
		buffer.Write(buf[:n])

		_, err = conn.Write(buffer.Bytes())
		if err != nil {
			log.Errorf("UDP failed to write back: %v\n", err)
			break
		}
	}
}
