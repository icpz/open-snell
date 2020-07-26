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

package aead

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

type Cipher interface {
	KeySize() int
	SaltSize() int
	Encrypter(salt []byte) (cipher.AEAD, error)
	Decrypter(salt []byte) (cipher.AEAD, error)
}

type snellCipher struct {
	psk      []byte
	keySize  int
	makeAEAD func(key []byte) (cipher.AEAD, error)
}

func (sc *snellCipher) KeySize() int  { return sc.keySize }
func (sc *snellCipher) SaltSize() int { return 16 }
func (sc *snellCipher) Encrypter(salt []byte) (cipher.AEAD, error) {
	return sc.makeAEAD(snellKDF(sc.psk, salt, sc.KeySize()))
}
func (sc *snellCipher) Decrypter(salt []byte) (cipher.AEAD, error) {
	return sc.makeAEAD(snellKDF(sc.psk, salt, sc.KeySize()))
}

func snellKDF(psk, salt []byte, keySize int) []byte {
	return argon2.IDKey(psk, salt, 3, 8, 1, 32)[:keySize]
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func NewAES128GCM(psk []byte) Cipher {
	return &snellCipher{
		psk:      psk,
		keySize:  16,
		makeAEAD: aesGCM,
	}
}

func NewChacha20Poly1305(psk []byte) Cipher {
	return &snellCipher{
		psk:      psk,
		keySize:  32,
		makeAEAD: chacha20poly1305.New,
	}
}
