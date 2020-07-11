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

package main

import (
    "flag"
    "net"
    "io"
    "os"
    "os/signal"
    "time"
    "syscall"

    log "github.com/golang/glog"
    "gopkg.in/ini.v1"

    "github.com/icpz/open-snell/components/snell"
    "github.com/icpz/open-snell/components/socks5"
)

var (
    configFile string
    listenAddr string
    serverAddr string
    obfsType   string
    obfsHost   string
    psk        string
)

func init() {
    flag.StringVar(&configFile, "c", "", "configuration file path")
    flag.StringVar(&listenAddr, "l", "0.0.0.0:18888", "client listen address")
    flag.StringVar(&serverAddr, "s", "", "snell server address")
    flag.StringVar(&obfsType, "obfs", "", "obfs type")
    flag.StringVar(&obfsHost, "obfs-host", "bing.com", "obfs host")
    flag.StringVar(&psk, "k", "", "pre-shared key")

    flag.Parse()
    flag.Set("logtostderr", "true")

    if configFile != "" {
        log.Infof("Configuration file specified, ignoring other flags\n")
        cfg, err := ini.Load(configFile)
        if err != nil {
            log.Fatalf("Failed to load config file %s, %s\n", configFile, err.Error())
        }
        sec, err := cfg.GetSection("snell-client")
        if err != nil {
            log.Fatalf("Section 'snell-client' not found in config file %s\n", configFile)
        }

        listenAddr = sec.Key("listen").String()
        serverAddr = sec.Key("server").String()
        obfsType   = sec.Key("obfs").String()
        obfsHost   = sec.Key("obfs-host").String()
        psk        = sec.Key("psk").String()
    }

    if serverAddr == "" {
        log.Fatalf("Invalid emtpy server address.\n")
    }

    if obfsHost == "" {
        log.Infof("Note: obfs host empty, using default bing.com\n")
        obfsHost = "bing.com"
    }
}

func main() {
    sn, err := snell.NewSnellClient(serverAddr, psk, obfsType, obfsHost)
    if err != nil {
        log.Fatalf("Failed to initialize snell client %s\n", err.Error())
    }

    cb := func (client net.Conn, addr socks5.Addr) {
        target, err := sn.Dial(addr.String())
        log.V(1).Infof("New target from %s to %s\n", client.RemoteAddr().String(), addr.String())
        if err != nil {
            log.Warningf("Failed to connect to target %s, error %s\n", addr.String(), err.Error())
            client.Close()
            return
        }

        relay(client, target)
        log.V(1).Infof("Session from %s done\n", client.RemoteAddr().String())
    }

    ls, err := socks5.NewSocksProxy(listenAddr, cb)
    if err != nil {
        log.Fatalf("Failed to listen on %s, error %s\n", listenAddr, err.Error())
    }

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh

    ls.Close()
}

func relay(left, right net.Conn) {
    ch := make(chan error)

    go func() {
        buf := make([]byte, 8192)
        _, err := io.CopyBuffer(left, right, buf)
        left.SetReadDeadline(time.Now())
        ch <- err
    }()

    buf := make([]byte, 8192)
    io.CopyBuffer(right, left, buf)
    right.SetReadDeadline(time.Now())
    <-ch
}
