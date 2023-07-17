package storage

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"

	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/bls"
	ttC "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
)

type clockMsgNotaImpl struct {
	aggSig           *bls.Signature
	epoch            blocksn.Epoch
	proposerIdx      uint16
	nVote            uint16
	missingVoterIdxs []uint16
	// Cache: should not be serialized.
	statusMutex sync.Mutex
	vStatus     verificationStatus
}

func (c *clockMsgNotaImpl) ImplementsClockMsgNota() {
}

func (c *clockMsgNotaImpl) GetType() tt.Type {
	return tt.TypeClockMsgNota
}

func (c *clockMsgNotaImpl) GetBody() []byte {
	var out [][]byte
	out = append(out, c.epoch.ToBytes())
	out = append(out, c.aggSig.ToBytes())
	out = append(out, ttC.Uint16ToBytes(c.proposerIdx))
	out = append(out, ttC.Uint16ToBytes(c.GetNVote()))
	out = append(out, ttC.Uint16ToBytes(uint16(len(c.missingVoterIdxs))))
	for _, v := range c.missingVoterIdxs {
		out = append(out, ttC.Uint16ToBytes(v))
	}
	return ttC.ConcatCopyPreAllocate(out)
}

func (c *clockMsgNotaImpl) GetBlockSn() blocksn.BlockSn {
	return blocksn.BlockSn{Epoch: c.epoch, S: 1}
}

func (c *clockMsgNotaImpl) GetDebugString() string {
	return c.String()
}

func (c *clockMsgNotaImpl) String() string {
	return fmt.Sprintf("clockMsgNotaImpl{%s,%d,%d,%d}", c.epoch, c.proposerIdx, c.nVote, c.missingVoterIdxs)
}

func (c *clockMsgNotaImpl) GetEpoch() blocksn.Epoch {
	return c.epoch
}

func (c *clockMsgNotaImpl) GetNVote() uint16 {
	return c.nVote
}

func (c *clockMsgNotaImpl) equals(v *clockMsgNotaImpl) bool {
	return bytes.Equal(c.aggSig.ToBytes(), v.aggSig.ToBytes()) &&
		c.epoch.Compare(v.GetEpoch()) == 0 &&
		c.proposerIdx == v.proposerIdx &&
		c.nVote == v.nVote &&
		reflect.DeepEqual(c.missingVoterIdxs, v.missingVoterIdxs)
}

func (c *clockMsgNotaImpl) setStatus(s verificationStatus) {
	c.statusMutex.Lock()
	defer c.statusMutex.Unlock()
	if c.vStatus != unknown {
		debug.Bug("unexpected call: clockMsgNotaImpl.setStatus should be called only once")
	}
	c.vStatus = s
}

func (c *clockMsgNotaImpl) getStatus() verificationStatus {
	c.statusMutex.Lock()
	defer c.statusMutex.Unlock()
	return c.vStatus
}

func NewClockMsgNotaImpl(e blocksn.Epoch, pSigner bls.BlsSigner, pIdx uint16, vSigners []*bls.SigningKey, missingVIdxs []uint16) tt.ClockMsgNota {
	aggSig, aggPk := pSigner.Sign(e.ToBytes()), pSigner.GetPublicKey()
	for _, s := range vSigners {
		sig := s.Sign(e.ToBytes())
		aggSig, aggPk = bls.CombineSignatures(aggSig, sig, aggPk, s.GetPublicKey())
	}
	return &clockMsgNotaImpl{
		aggSig:           aggSig,
		epoch:            e,
		proposerIdx:      pIdx,
		nVote:            uint16(len(vSigners)),
		missingVoterIdxs: missingVIdxs,
	}
}
