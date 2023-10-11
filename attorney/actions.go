// ami actions implements the authentication functionality on top of breeze
// void action.

package attorney

import (
	"encoding/json"

	"github.com/freehandle/breeze/crypto"
	"github.com/freehandle/breeze/protocol/actions"
	"github.com/freehandle/breeze/util"
)

var AxeProtocolCode = [4]byte{1, 0, 0, 0}

type ActionValidator interface {
	Epoch() uint64
	HasCaption(crypto.Hash) bool
	HasMember(crypto.Hash) bool
	SetNewMember(crypto.Hash, crypto.Hash) bool
	PowerOfAttorney(crypto.Hash) bool
	SetNewGrantPower(crypto.Hash) bool
	SetNewRevokePower(crypto.Hash) bool
}

func GetTokens(data []byte) []crypto.Token {
	kind := Kind(data)
	switch kind {
	case JoinNetworkType:
		if join := ParseJoinNetwork(data); join != nil {
			return join.Tokens()
		}

	case UpdateInfoType:
		if update := ParseUpdateInfo(data); update != nil {
			return update.Tokens()
		}
	case GrantPowerOfAttorneyType:
		if grant := ParseGrantPowerOfAttorney(data); grant != nil {
			return grant.Tokens()
		}
	case RevokePowerOfAttorneyType:
		if revoke := ParseRevokePowerOfAttorney(data); revoke != nil {
			return revoke.Tokens()
		}
	case VoidType:
		if void := ParseVoid(data); void != nil {
			return void.Tokens()
		}
	}
	return nil
}

const (
	VoidType byte = iota
	JoinNetworkType
	UpdateInfoType
	GrantPowerOfAttorneyType
	RevokePowerOfAttorneyType
	Invalid
)

func Kind(data []byte) byte {
	if len(data) < 12 {
		return Invalid
	}
	if data[0] != 0 || data[1] != actions.IVoid || data[10]&1 != 1 {
		return Invalid
	}
	if data[11] >= Invalid {
		return Invalid
	}
	return data[11]
}

type JoinNetwork struct {
	Epoch     uint64
	Author    crypto.Token
	Handle    string
	Details   string
	Signature crypto.Signature
}

func (j *JoinNetwork) Tokens() []crypto.Token {
	return []crypto.Token{j.Author}
}

func (j *JoinNetwork) Validate(v ActionValidator) bool {
	captionHash := crypto.Hasher([]byte(j.Handle))
	if v.HasCaption(captionHash) {
		return false
	}
	authorHash := crypto.Hasher(j.Author[:])
	if v.HasMember(authorHash) {
		return false
	}
	if !json.Valid([]byte(j.Details)) {
		return false
	}
	return v.SetNewMember(authorHash, captionHash)
}

func (j *JoinNetwork) Kind() byte {
	return JoinNetworkType
}

func (j *JoinNetwork) Serialize() []byte {
	bytes := []byte{0, actions.IVoid} // breeze (version 0) void action
	util.PutUint64(j.Epoch, &bytes)
	util.PutByteArray([]byte{1, 0, 0, 0}, &bytes) // axé (version 0) protocol
	util.PutByte(JoinNetworkType, &bytes)
	util.PutToken(j.Author, &bytes)
	util.PutString(j.Handle, &bytes)
	util.PutString(j.Details, &bytes)
	util.PutSignature(j.Signature, &bytes)
	return bytes
}

func ParseJoinNetwork(data []byte) *JoinNetwork {
	if data[0] != 0 || data[1] != 0 {
		return nil
	}
	join := JoinNetwork{}
	position := 1
	join.Epoch, position = util.ParseUint64(data, position)
	if len(data) <= position+1 || data[position] != 0 || data[position+1] != JoinNetworkType {
		return nil
	}
	position += 2
	join.Author, position = util.ParseToken(data, position)
	join.Handle, position = util.ParseString(data, position)
	join.Details, position = util.ParseString(data, position)
	if !json.Valid([]byte(join.Details)) {
		return nil
	}
	hashPosition := position
	join.Signature, position = util.ParseSignature(data, position)
	if position != len(data) {
		return nil
	}
	if !join.Author.Verify(data[0:hashPosition], join.Signature) {
		return nil
	}
	return &join
}

type UpdateInfo struct {
	Epoch     uint64
	Author    crypto.Token
	Details   string
	Signer    crypto.Token
	Signature crypto.Signature
}

func (u *UpdateInfo) Tokens() []crypto.Token {
	if u.Signer.Equal(u.Author) {
		return []crypto.Token{u.Author}
	} else {
		return []crypto.Token{u.Author, u.Signer}
	}
}

func (u *UpdateInfo) Validate(v ActionValidator) bool {
	if !v.HasMember(crypto.HashToken(u.Author)) {
		return false
	}
	if !u.Signer.Equal(u.Author) {
		hash := crypto.Hasher(append(u.Author[:], u.Signer[:]...))
		if !v.PowerOfAttorney(hash) {
			return false
		}
	}
	return json.Valid([]byte(u.Details))
}

func (u *UpdateInfo) Kind() byte {
	return UpdateInfoType
}

func (u *UpdateInfo) Serialize() []byte {
	bytes := []byte{0, 0}
	util.PutUint64(u.Epoch, &bytes)
	util.PutByte(UpdateInfoType, &bytes)
	util.PutToken(u.Author, &bytes)
	util.PutString(u.Details, &bytes)
	util.PutToken(u.Signer, &bytes)
	util.PutSignature(u.Signature, &bytes)
	return bytes
}

func ParseUpdateInfo(data []byte) *UpdateInfo {
	if data[0] != 0 || data[1] != 0 {
		return nil
	}
	update := UpdateInfo{}
	position := 1
	update.Epoch, position = util.ParseUint64(data, position)
	if len(data) <= position+1 || data[position] != 0 || data[position+1] != UpdateInfoType {
		return nil
	}
	position += 2
	update.Author, position = util.ParseToken(data, position)
	update.Details, position = util.ParseString(data, position)
	if !json.Valid([]byte(update.Details)) {
		return nil
	}
	update.Signer, position = util.ParseToken(data, position)
	hashPosition := position
	update.Signature, position = util.ParseSignature(data, position)
	if position != len(data) {
		return nil
	}
	if !update.Author.Verify(data[0:hashPosition], update.Signature) {
		return nil
	}
	return &update
}

type GrantPowerOfAttorney struct {
	Epoch     uint64
	Author    crypto.Token
	Attorney  crypto.Token
	Signature crypto.Signature
}

func (g *GrantPowerOfAttorney) Tokens() []crypto.Token {
	return []crypto.Token{g.Author, g.Attorney}
}

func (g *GrantPowerOfAttorney) Validate(v ActionValidator) bool {
	if !v.HasMember(crypto.HashToken(g.Author)) {
		return false
	}
	hash := crypto.Hasher(append(g.Author[:], g.Attorney[:]...))
	if v.PowerOfAttorney(hash) {
		return false
	}
	return v.SetNewGrantPower(hash)
}

func (g *GrantPowerOfAttorney) Kind() byte {
	return GrantPowerOfAttorneyType
}

func (g *GrantPowerOfAttorney) Serialize() []byte {
	bytes := []byte{0, 0}
	util.PutUint64(g.Epoch, &bytes)
	util.PutByte(GrantPowerOfAttorneyType, &bytes)
	util.PutToken(g.Author, &bytes)
	util.PutToken(g.Attorney, &bytes)
	util.PutSignature(g.Signature, &bytes)
	return bytes
}

func ParseGrantPowerOfAttorney(data []byte) *GrantPowerOfAttorney {
	if data[0] != 0 || data[1] != 0 {
		return nil
	}
	grant := GrantPowerOfAttorney{}
	position := 1
	grant.Epoch, position = util.ParseUint64(data, position)
	if len(data) <= position+1 || data[position] != 0 || data[position+1] != GrantPowerOfAttorneyType {
		return nil
	}
	position += 2
	grant.Author, position = util.ParseToken(data, position)
	grant.Attorney, position = util.ParseToken(data, position)
	hashPosition := position
	grant.Signature, position = util.ParseSignature(data, position)
	if position != len(data) {
		return nil
	}
	if !grant.Author.Verify(data[0:hashPosition], grant.Signature) {
		return nil
	}
	return &grant
}

type RevokePowerOfAttorney struct {
	Epoch     uint64
	Author    crypto.Token
	Attorney  crypto.Token
	Signature crypto.Signature
}

func (r *RevokePowerOfAttorney) Tokens() []crypto.Token {
	return []crypto.Token{r.Author, r.Attorney}
}

func (r *RevokePowerOfAttorney) Validate(v ActionValidator) bool {
	if !v.HasMember(crypto.HashToken(r.Author)) {
		return false
	}
	hash := crypto.Hasher(append(r.Author[:], r.Attorney[:]...))
	if !v.PowerOfAttorney(hash) {
		return false
	}
	return v.SetNewRevokePower(hash)
}

func (r *RevokePowerOfAttorney) Kind() byte {
	return RevokePowerOfAttorneyType
}

func (r *RevokePowerOfAttorney) Serialize() []byte {
	bytes := []byte{0, 0}
	util.PutUint64(r.Epoch, &bytes)
	util.PutByte(RevokePowerOfAttorneyType, &bytes)
	util.PutToken(r.Author, &bytes)
	util.PutToken(r.Attorney, &bytes)
	util.PutSignature(r.Signature, &bytes)
	return bytes
}

func ParseRevokePowerOfAttorney(data []byte) *RevokePowerOfAttorney {
	if data[0] != 0 || data[1] != 0 {
		return nil
	}
	revoke := RevokePowerOfAttorney{}
	position := 1
	revoke.Epoch, position = util.ParseUint64(data, position)
	if len(data) <= position+1 || data[position] != 0 || data[position+1] != RevokePowerOfAttorneyType {
		return nil
	}
	position += 2
	revoke.Author, position = util.ParseToken(data, position)
	revoke.Attorney, position = util.ParseToken(data, position)
	hashPosition := position
	revoke.Signature, position = util.ParseSignature(data, position)
	if position != len(data) {
		return nil
	}
	if !revoke.Author.Verify(data[0:hashPosition], revoke.Signature) {
		return nil
	}
	return &revoke
}

type Void struct {
	Epoch     uint64
	Author    crypto.Token
	Data      []byte
	Signer    crypto.Token
	Signature crypto.Signature
}

func (g *Void) Tokens() []crypto.Token {
	if g.Author.Equal(g.Signer) {
		return []crypto.Token{g.Author}
	} else {
		return []crypto.Token{g.Author, g.Signer}
	}
}

func (void *Void) Validate(v ActionValidator) bool {
	if void.Epoch > v.Epoch() {
		return false
	}
	if !v.HasMember(crypto.HashToken(void.Author)) {
		return false
	}
	if !void.Signer.Equal(void.Author) {
		hash := crypto.Hasher(append(void.Author[:], void.Signer[:]...))
		if !v.PowerOfAttorney(hash) {
			return false
		}
	}
	return true
}

func (v *Void) Kind() byte {
	return VoidType
}

func (v *Void) Serialize() []byte {
	bytes := []byte{0, 0}
	util.PutUint64(v.Epoch, &bytes)
	util.PutByte(VoidType, &bytes)
	util.PutByteArray(v.Data, &bytes)
	util.PutToken(v.Signer, &bytes)
	util.PutSignature(v.Signature, &bytes)
	return bytes
}

func ParseVoid(data []byte) *Void {
	if data[0] != 0 || data[1] != 0 {
		return nil
	}
	void := Void{}
	position := 1
	void.Epoch, position = util.ParseUint64(data, position)
	if len(data) <= position+1 || data[position] != 0 || data[position+1] != VoidType {
		return nil
	}
	position += 2
	void.Author, position = util.ParseToken(data, position)
	void.Data, position = util.ParseByteArray(data, position)
	void.Signer, position = util.ParseToken(data, position)
	hashPosition := position
	void.Signature, position = util.ParseSignature(data, position)
	if position != len(data) {
		return nil
	}
	if !void.Signer.Verify(data[0:hashPosition], void.Signature) {
		return nil
	}
	return &void
}

type KeyExchange struct {
	Epoch     uint64
	Author    crypto.Token
	To        crypto.Token
	Ephemeral crypto.Token
	Secret    []byte
	Attorney  crypto.Token
}
