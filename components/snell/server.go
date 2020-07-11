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
    "fmt"
    "io"
    "net"
    "strconv"
    "syscall"

    log "github.com/golang/glog"
    "github.com/Dreamacro/go-shadowsocks2/shadowaead"
    "golang.org/x/crypto/chacha20poly1305"

    obfs "github.com/icpz/open-snell/components/simple-obfs"
    "github.com/icpz/open-snell/components/utils"
)

const (
    CommandPing    byte = 0
    CommandConnect byte = 1

    ResponseTunnel byte = 0
    ResponsePong   byte = 1
    ResponseError  byte = 2

    Version byte = 1
)

type SnellServer struct {
    listener net.Listener
    psk []byte
    closed bool
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
    if _, err = io.ReadFull(c, buf[:clen + 1]); err != nil {
        return
    }

    if clen > 0 {
        log.V(1).Infof("client id %s\n", string(buf[:clen]))
    }

    hlen := buf[clen]
    if _, err = io.ReadFull(c, buf[:hlen + 2]); err != nil {
        return
    }
    host := string(buf[:hlen])
    port := strconv.Itoa((int(buf[hlen]) << 8) | int(buf[hlen + 1]))
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

    bpsk := []byte(psk)
    ss := &SnellServer{l, bpsk, false}
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
            switch obfsType {
            case "tls":
                c = obfs.NewTLSObfsServer(c)
            case "http":
                c = obfs.NewHTTPObfsServer(c)
            }
            c = shadowaead.NewConn(c, &snellCipher{bpsk, chacha20poly1305.New})
            go ss.handleSnell(c)
        }
    }()

    return ss, nil
}

func (s *SnellServer) handleSnell(conn net.Conn) {
    defer conn.Close()

    target, command, err := s.ServerHandshake(conn)
    if err != nil {
        log.Warningf("Failed to handshake %s\n", err.Error())
        return
    }
    log.V(1).Infof("New target from %s to %s\n", conn.RemoteAddr().String(), target)

    if c, ok := conn.(*net.TCPConn); ok {
        c.SetKeepAlive(true)
    }

    if command == CommandPing {
        buf := []byte{ResponsePong}
        conn.Write(buf)
        return
    }

    if command != CommandConnect {
        log.Errorf("Unknown command 0x%x\n", command)
        return
    }

    tc, err := net.Dial("tcp", target)
    if err != nil {
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
        conn.Write(buf.Bytes())
        return
    }

    conn.Write([]byte{ResponseTunnel})
    utils.Relay(conn, tc)
    log.V(1).Infof("Session from %s done", conn.RemoteAddr().String())
}
