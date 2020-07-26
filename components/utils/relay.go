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

package utils

import (
	"io"
	"net"
	"time"

	p "github.com/icpz/open-snell/components/utils/pool"
)

func Relay(left, right net.Conn) (el, er error) {
	ch := make(chan error)

	go func() {
		buf := p.Get(p.RelayBufferSize)
		_, err := io.CopyBuffer(left, right, buf)
		p.Put(buf)
		left.SetReadDeadline(time.Now())
		ch <- err
	}()

	buf := p.Get(p.RelayBufferSize)
	_, el = io.CopyBuffer(right, left, buf)
	p.Put(buf)
	right.SetReadDeadline(time.Now())
	er = <-ch

	if err, ok := el.(net.Error); ok && err.Timeout() {
		el = nil
	}
	if err, ok := er.(net.Error); ok && err.Timeout() {
		er = nil
	}

	return
}
