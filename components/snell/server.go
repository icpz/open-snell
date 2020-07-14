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

    obfs "github.com/icpz/open-snell/components/simple-obfs"
    p "github.com/icpz/open-snell/components/utils/pool"
    "github.com/icpz/open-snell/components/utils"
    "github.com/icpz/open-snell/components/aead"
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

    for isV2 {
        target, command, err := s.ServerHandshake(conn)
        if err != nil {
            if err != io.EOF {
                log.Warningf("Failed to handshake from %s: %s\n", conn.RemoteAddr().String(), err.Error())
            }
            break
        }
        log.V(1).Infof("New target from %s to %s\n", conn.RemoteAddr().String(), target)

        if c, ok := conn.(*net.TCPConn); ok {
            c.SetKeepAlive(true)
        }

        if command == CommandPing {
            buf := []byte{ResponsePong}
            conn.Write(buf)
            break
        }

        if command == CommandConnect {
            isV2 = false
        } else if command != CommandConnectV2 {
            log.Errorf("Unknown command 0x%x\n", command)
            break
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
            if isV2 {
                conn.Write([]byte{})
            }
            continue
        }

        conn.Write([]byte{ResponseTunnel})
        el, _ := utils.Relay(conn, tc)

        tc.Close()
        if isV2 {
            conn.SetReadDeadline(time.Time{})
            _, err := conn.Write([]byte{}) // write zero chunk back
            if err != nil {
                log.Errorf("Unexpected write error %s\n", err.Error())
                conn.Close()
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
                log.Warningf("Unexpected error %s, ZERO CHUNK wanted\n", el.Error())
                break
            }
        }
    }

    log.V(1).Infof("Session from %s done", conn.RemoteAddr().String())
}
