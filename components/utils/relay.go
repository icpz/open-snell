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
)

func Relay(left, right net.Conn) {
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
