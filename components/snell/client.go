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
    "fmt"
    "net"
    "strconv"

    obfs "github.com/Dreamacro/clash/component/simple-obfs"
    "github.com/Dreamacro/clash/component/snell"
)

type SnellClient struct {
    server string
    psk []byte
    obfs string
    obfsHost string
}

func (s *SnellClient) StreamConn(c net.Conn, target string) (net.Conn, error) {
    switch s.obfs {
    case "tls":
        c = obfs.NewTLSObfs(c, s.obfsHost)
    case "http":
        _, port, _ := net.SplitHostPort(s.server)
        c = obfs.NewHTTPObfs(c, s.obfsHost, port)
    }
    c = snell.StreamConn(c, s.psk)
    host, port, _ := net.SplitHostPort(target)
    iport, _ := strconv.Atoi(port)
    err := snell.WriteHeader(c, host, uint(iport))
    return c, err
}

func (s *SnellClient) Dial(target string) (net.Conn, error) {
    c, err := net.Dial("tcp", s.server)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to snell server %s", err.Error())
    }

    return s.StreamConn(c, target)
}

func NewSnellClient(server, psk, obfs, obfsHost string) (*SnellClient, error) {
    if obfs != "tls" && obfs != "http" && obfs != "" {
        return nil, fmt.Errorf("invalid snell obfs type %s", obfs)
    }

    if obfsHost == "" {
        obfsHost = "www.bing.com"
    }

    return &SnellClient {
        server: server,
        psk: []byte(psk),
        obfs: obfs,
        obfsHost: obfsHost,
    }, nil
}

