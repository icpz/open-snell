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
	"os"
	"os/signal"
	"syscall"

	log "github.com/golang/glog"
	"gopkg.in/ini.v1"

	"github.com/icpz/open-snell/components/snell"
	"github.com/icpz/open-snell/constants"
)

var (
	configFile string
	listenAddr string
	obfsType   string
	psk        string
	version    bool
)

func init() {
	flag.StringVar(&configFile, "c", "", "configuration file path")
	flag.StringVar(&listenAddr, "l", "0.0.0.0:18888", "server listen address")
	flag.StringVar(&obfsType, "obfs", "", "obfs type")
	flag.StringVar(&psk, "k", "", "pre-shared key")
	flag.BoolVar(&version, "version", false, "show open-snell version")

	flag.Parse()
	flag.Set("logtostderr", "true")

	log.Infof("Open-snell server, version: %s\n", constants.Version)
	if version {
		os.Exit(0)
	}

	if configFile != "" {
		log.Infof("Configuration file specified, ignoring other flags\n")
		cfg, err := ini.Load(configFile)
		if err != nil {
			log.Fatalf("Failed to load config file %s, %v\n", configFile, err)
		}
		sec, err := cfg.GetSection("snell-server")
		if err != nil {
			log.Fatalf("Section 'snell-server' not found in config file %s\n", configFile)
		}

		listenAddr = sec.Key("listen").String()
		obfsType = sec.Key("obfs").String()
		psk = sec.Key("psk").String()
	}

	if obfsType == "none" || obfsType == "off" {
		obfsType = ""
	}
}

func main() {
	sn, err := snell.NewSnellServer(listenAddr, psk, obfsType)
	if err != nil {
		log.Fatalf("Failed to initialize snell server %v\n", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	sn.Close()
}
