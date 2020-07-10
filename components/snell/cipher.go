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
    "crypto/cipher"

    "golang.org/x/crypto/argon2"
)

type snellCipher struct {
    psk      []byte
    makeAEAD func(key []byte) (cipher.AEAD, error)
}

func (sc *snellCipher) KeySize() int  { return 32 }
func (sc *snellCipher) SaltSize() int { return 16 }
func (sc *snellCipher) Encrypter(salt []byte) (cipher.AEAD, error) {
    return sc.makeAEAD(argon2.IDKey(sc.psk, salt, 3, 8, 1, uint32(sc.KeySize())))
}
func (sc *snellCipher) Decrypter(salt []byte) (cipher.AEAD, error) {
    return sc.makeAEAD(argon2.IDKey(sc.psk, salt, 3, 8, 1, uint32(sc.KeySize())))
}
