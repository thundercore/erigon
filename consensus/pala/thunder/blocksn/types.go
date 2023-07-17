package blocksn

import (
	"encoding/binary"
	"fmt"

	"github.com/petar/GoLLRB/llrb"
)

type BlockSnGetter interface {
	GetBlockSn() BlockSn
}

type BlockSn struct {
	Epoch Epoch
	// Estimate a rough lower bound: (2**32-1) / (86400*365) == 136.19 (years)
	// uint32 is large enough.
	S uint32
}

func NewBlockSn(session, epoch, s uint32) BlockSn {
	return BlockSn{
		Epoch: NewEpoch(session, epoch),
		S:     s,
	}
}

func (s BlockSn) ToBytes() []byte {
	bytes := make([]byte, 12)
	// Instead of calling Epoch.ToBytes(), write to bytes directly to avoid an unnecessary copy.
	binary.LittleEndian.PutUint32(bytes, uint32(s.Epoch.Session))
	binary.LittleEndian.PutUint32(bytes[4:], s.Epoch.E)
	binary.LittleEndian.PutUint32(bytes[8:], s.S)
	return bytes
}

func (s BlockSn) String() string {
	return fmt.Sprintf("(%d,%d,%d)", s.Epoch.Session, s.Epoch.E, s.S)
}

func (s BlockSn) IsGenesis() bool {
	return s.Epoch.IsNil() && s.S == 1
}

func (s BlockSn) IsPala() bool {
	return s.Epoch.Session > 0
}

func (s BlockSn) IsNil() bool {
	return s.Epoch.IsNil() && s.S == 0
}

func (s BlockSn) Compare(s2 BlockSn) int {
	r := s.Epoch.Compare(s2.Epoch)
	if r != 0 {
		return r
	}
	if s.S != s2.S {
		if s.S < s2.S {
			return -1
		} else {
			return 1
		}
	}
	return 0
}

func (s BlockSn) GetBlockSn() BlockSn {
	return s
}

func (s BlockSn) Less(s2 llrb.Item) bool {
	return s.Compare(s2.(BlockSnGetter).GetBlockSn()) < 0
}

func (s BlockSn) NextS() BlockSn {
	return BlockSn{
		Epoch: s.Epoch,
		S:     s.S + 1,
	}
}

type Epoch struct {
	// session in (session, epoch, s),
	// where `session` is the `sid` from the "Reconfigurable Pala" section of the paper.
	Session Session
	// epoch   in (session, epoch, s)
	E uint32
}

func NewEpoch(session, e uint32) Epoch {
	return Epoch{
		Session: Session(session),
		E:       e,
	}
}

func (e Epoch) ToBytes() []byte {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(bytes, uint32(e.Session))
	binary.LittleEndian.PutUint32(bytes[4:], e.E)
	return bytes
}

func (e Epoch) Compare(e2 Epoch) int {
	if e.Session < e2.Session {
		return -1
	} else if e.Session > e2.Session {
		return 1
	}
	if e.E < e2.E {
		return -1
	} else if e.E > e2.E {
		return 1
	}
	return 0
}

func (e Epoch) IsNil() bool {
	return e.Session == 0 && e.E == 0
}

func (e Epoch) String() string {
	return fmt.Sprintf("(%d,%d)", e.Session, e.E)
}

func (e Epoch) NextSession() Epoch {
	return Epoch{e.Session + 1, 1}
}

func (e Epoch) NextEpoch() Epoch {
	return Epoch{e.Session, e.E + 1}
}

func (e Epoch) PreviousEpoch() (Epoch, error) {
	if e.E > 1 {
		return Epoch{e.Session, e.E - 1}, nil
	}
	return Epoch{}, fmt.Errorf(
		"don't know the last epoch because %s is the first epoch of this session", e)
}

func (s Session) String() string {
	return fmt.Sprintf("%d", s)
}

type Session uint32
