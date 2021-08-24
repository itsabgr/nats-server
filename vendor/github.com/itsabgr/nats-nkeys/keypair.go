// Copyright 2018 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nkeys

import (
	"crypto/rand"
	"github.com/itsabgr/nats-nkeys/pkg/secp256k1"
	tmcrypto "github.com/tendermint/tendermint/crypto"
	"io"
)

// kp is the internal struct for a kepypair using seed.
type kp2 struct {
	seed []byte
}

// CreatePair will create a KeyPair based on the rand entropy and a type/prefix byte. rand can be nil.
func CreatePair(prefix PrefixByte) (KeyPair, error) {
	var rawSeed [32]byte

	_, err := io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		return nil, err
	}

	seed, err := EncodeSeed(prefix, rawSeed[:])
	if err != nil {
		return nil, err
	}
	return &kp2{seed}, nil
}

// rawSeed will return the raw, decoded 64 byte seed.
func (pair *kp2) rawSeed() ([]byte, error) {
	_, raw, err := DecodeSeed(pair.seed)
	return raw, err
}

// keys will return a 32 byte public key and a 64 byte private key utilizing the seed.
func (pair *kp2) keys() (tmcrypto.PubKey, tmcrypto.PrivKey, error) {
	raw, err := pair.rawSeed()
	if err != nil {
		return nil, nil, err
	}
	pv := secp256k1.GenPrivKeySecp256k1(raw)
	return pv.PubKey(), pv, nil
}

// Wipe will randomize the contents of the seed key
func (pair *kp2) Wipe() {
	io.ReadFull(rand.Reader, pair.seed)
	pair.seed = nil
}

// Seed will return the encoded seed.
func (pair *kp2) Seed() ([]byte, error) {
	return pair.seed, nil
}

// PublicKey will return the encoded public key associated with the KeyPair.
// All KeyPairs have a public key.
func (pair *kp2) PublicKey() (string, error) {
	public, raw, err := DecodeSeed(pair.seed)
	if err != nil {
		return "", err
	}
	pub := secp256k1.GenPrivKeySecp256k1(raw).PubKey()
	pk, err := Encode(public, pub.Bytes())
	if err != nil {
		return "", err
	}
	return string(pk), nil
}

// PrivateKey will return the encoded private key for KeyPair.
func (pair *kp2) PrivateKey() ([]byte, error) {
	_, priv, err := pair.keys()
	if err != nil {
		return nil, err
	}
	return Encode(PrefixBytePrivate, priv.Bytes())
}

// Sign will sign the input with KeyPair's private key.
func (pair *kp2) Sign(input []byte) ([]byte, error) {
	_, priv, err := pair.keys()
	if err != nil {
		return nil, err
	}
	return priv.Sign(input)
}

// Verify will verify the input against a signature utilizing the public key.
func (pair *kp2) Verify(input []byte, sig []byte) error {
	pub, _, err := pair.keys()
	if err != nil {
		return err
	}
	if !pub.VerifySignature(input, sig) {
		return ErrInvalidSignature
	}
	return nil
}
