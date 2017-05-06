// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package disk

type RatchetState struct {
	RootKey            []byte
	SendHeaderKey      []byte
	RecvHeaderKey      []byte
	NextSendHeaderKey  []byte
	NextRecvHeaderKey  []byte
	SendChainKey       []byte
	RecvChainKey       []byte
	SendRatchetPrivate []byte
	RecvRatchetPublic  []byte
	SendCount          uint32
	RecvCount          uint32
	PrevSendCount      uint32
	Ratchet            bool
	Private            []byte
	MyHalf             []byte
	TheirHalf          []byte
	SavedKeys          []RatchetState_SavedKeys
}

type RatchetState_SavedKeys struct {
	HeaderKey   []byte
	MessageKeys []RatchetState_SavedKeys_MessageKey
}

type RatchetState_SavedKeys_MessageKey struct {
	Num          uint32
	Key          []byte
	CreationTime int64
}
