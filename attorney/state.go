package attorney

import (
	"github.com/freehandle/breeze/crypto"
)

type State struct {
	Members   *hashVault
	Captions  *hashVault
	Attorneys *hashVault
}

func NewGenesisState(dataPath string) *State {
	state := State{
		Members:   NewHashVault("members", 0, 8, dataPath),
		Captions:  NewHashVault("captions", 0, 8, dataPath),
		Attorneys: NewHashVault("poa", 0, 8, dataPath),
	}
	return &state
}

func (s *State) Validator(mutations ...*Mutations) *MutatingState {
	if len(mutations) == 0 {
		return &MutatingState{
			state:     s,
			mutations: NewMutations(),
		}
	}
	if len(mutations) > 1 {
		mutations[0].Merge(mutations[1:]...)
	}
	return &MutatingState{
		state:     s,
		mutations: mutations[0],
	}
}

func (s *State) Incorporate(mutations *Mutations) {
	if mutations == nil {
		return
	}
	for hash := range mutations.GrantPower {
		s.Attorneys.InsertHash(hash)
	}
	for hash := range mutations.RevokePower {
		s.Attorneys.RemoveHash(hash)
	}
	for hash := range mutations.NewMembers {
		s.Members.InsertHash(hash)
	}
	for hash := range mutations.NewCaption {
		s.Captions.ExistsHash(hash)
	}
}

func (s *State) ChecksumPoint() crypto.Hash {
	return crypto.ZeroHash
}

func (s *State) Recover() error {
	return nil
}

func (s *State) PowerOfAttorney(token, attorney crypto.Token) bool {
	if token.Equal(attorney) {
		return true
	}
	join := append(token[:], attorney[:]...)
	hash := crypto.Hasher(join)
	return s.Attorneys.ExistsHash(hash)
}

func (s *State) HasMember(token crypto.Token) bool {
	hash := crypto.HashToken(token)
	return s.Members.ExistsHash(hash)
}

func (s *State) HasHandle(handle string) bool {
	hash := crypto.Hasher([]byte(handle))
	return s.Captions.ExistsHash(hash)
}

func (s *State) Shutdown() {
	s.Members.Close()
	s.Attorneys.Close()
	s.Captions.Close()
}
