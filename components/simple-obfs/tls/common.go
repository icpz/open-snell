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

package tls

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	p "github.com/icpz/open-snell/components/utils/pool"
)

func init() {
	rand.Seed(time.Now().Unix())
}

const (
	chunkSize = 16 * 1024
)

var bufferPool = sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}

// read a [length][data...] block
func readBlock(c net.Conn, b []byte, skipSize int) (remain, n int, err error) {
	if skipSize > 0 {
		buf := p.Get(skipSize)
		_, err = io.ReadFull(c, buf)
		p.Put(buf)
		if err != nil {
			return
		}
	}

	sizeBuf := make([]byte, 2)
	_, err = io.ReadFull(c, sizeBuf)
	if err != nil {
		return
	}

	length := (int(sizeBuf[0]) << 8) | int(sizeBuf[1])
	if length > len(b) {
		n, err = c.Read(b)
		remain = length - n
		return
	}

	n, err = io.ReadFull(c, b[:length])
	return
}
