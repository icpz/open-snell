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

const (
	CommandPing      byte = 0
	CommandConnect   byte = 1
	CommandConnectV2 byte = 5
	CommandUDP       byte = 6

	CommandUDPForward byte = 1

	ResponseTunnel byte = 0
	ResponseReady  byte = 0
	ResponsePong   byte = 1
	ResponseError  byte = 2

	Version byte = 1
)

type AppError struct {
	code byte
	msg  string
}

func (e *AppError) Error() string {
	return e.msg
}

func NewAppError(code byte, msg string) error {
	return &AppError{
		code: code,
		msg:  msg,
	}
}
