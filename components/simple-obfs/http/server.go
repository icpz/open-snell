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

package http

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"time"
)

type HTTPObfsServer struct {
	net.Conn
	buf           []byte
	bio           *bufio.Reader
	offset        int
	firstRequest  bool
	firstResponse bool
}

func (hos *HTTPObfsServer) Read(b []byte) (int, error) {
	if hos.buf != nil {
		n := copy(b, hos.buf[hos.offset:])
		hos.offset += n
		if hos.offset == len(hos.buf) {
			hos.offset = 0
			hos.buf = nil
		}
		return n, nil
	}

	if hos.firstRequest {
		bio := bufio.NewReader(hos.Conn)
		req, err := http.ReadRequest(bio)
		if err != nil {
			return 0, err
		}
		if req.Method != "GET" || req.Header.Get("Connection") != "Upgrade" {
			return 0, io.EOF
		}

		buf, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return 0, err
		}
		n := copy(b, buf)
		if n < len(buf) {
			hos.buf = buf
			hos.offset = n
		}
		req.Body.Close()
		hos.bio = bio
		hos.firstRequest = false
		return n, nil
	}

	return hos.bio.Read(b)
}

const httpResponseTemplate = "HTTP/1.1 101 Switching Protocols\r\n" +
	"Server: nginx/1.%d.%d\r\n" +
	"Date: %s\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Accept: %s\r\n" +
	"\r\n"

var vMajor = rand.Int() % 11
var vMinor = rand.Int() % 12

func (hos *HTTPObfsServer) Write(b []byte) (int, error) {
	if hos.firstResponse {
		randBytes := make([]byte, 16)
		rand.Read(randBytes)
		date := time.Now().Format(time.RFC1123)
		resp := fmt.Sprintf(httpResponseTemplate, vMajor, vMinor, date, base64.URLEncoding.EncodeToString(randBytes))
		_, err := hos.Conn.Write([]byte(resp))
		if err != nil {
			return 0, err
		}
		hos.firstResponse = false
		_, err = hos.Conn.Write(b)
		return len(b), err
	}
	return hos.Conn.Write(b)
}

func NewHTTPObfsServer(conn net.Conn) net.Conn {
	return &HTTPObfsServer{
		Conn:          conn,
		buf:           nil,
		bio:           nil,
		offset:        0,
		firstRequest:  true,
		firstResponse: true,
	}
}
