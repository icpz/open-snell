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
	"context"
	"errors"
	"net"

	"github.com/icpz/pool"
)

type snellFactory = func() (net.Conn, error)

type snellPool struct {
	pool *pool.Pool
}

func (p *snellPool) Get() (net.Conn, error) {
	i := p.pool.Get()
	switch e := i.(type) {
	case error:
		return nil, e
	case net.Conn:
		return &snellPoolConn{
			Conn: e,
			pool: p,
		}, nil
	}
	return nil, errors.New("Invalid Type")
}

func (p *snellPool) Close() {
	p.pool.ReleaseAll()
}

type snellPoolConn struct {
	net.Conn
	pool *snellPool
}

func (pc *snellPoolConn) Close() error {
	if pc.pool == nil {
		return pc.Conn.Close()
	}
	pc.pool.pool.Put(pc.Conn)
	return nil
}

func (pc *snellPoolConn) MarkUnusable() {
	pc.pool = nil
}

func newSnellPool(maxSize, leaseMS int, factory snellFactory) (*snellPool, error) {
	p := pool.New(
		func(ctx context.Context) interface{} {
			c, e := factory()
			if e != nil {
				return e
			}
			return c
		},
		pool.OptCapacity(maxSize),
		pool.OptLeaseMS(int64(leaseMS)),
		pool.OptDeleter(func(i interface{}) {
			if c, ok := i.(net.Conn); ok {
				c.Close()
			}
		}),
	)
	return &snellPool{p}, nil
}
