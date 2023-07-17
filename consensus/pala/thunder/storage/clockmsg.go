package storage

import (
	"bytes"
	"fmt"

	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/bls"
	ttC "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
)

type clockMsgImpl struct {
	epoch     blocksn.Epoch
	signature *bls.Signature
	voterId   tt.ConsensusId
}

func (c *clockMsgImpl) ImplementsClockMsg() {
}

func (c *clockMsgImpl) GetType() tt.Type {
	return tt.TypeClockMsg
}

func (c *clockMsgImpl) GetBody() []byte {
	bytes := ttC.StringToBytes(string(c.voterId))
	bytes = append(bytes, c.signature.ToBytes()...)
	return append(bytes, c.epoch.ToBytes()...)
}

func (c *clockMsgImpl) GetBlockSn() blocksn.BlockSn {
	return blocksn.BlockSn{Epoch: c.epoch, S: 1}
}

func (c *clockMsgImpl) GetDebugString() string {
	return c.String()
}

func (c *clockMsgImpl) String() string {
	return fmt.Sprintf("clockMsgImpl{%s,%s}", c.epoch, c.voterId)
}

func (c *clockMsgImpl) GetEpoch() blocksn.Epoch {
	return c.epoch
}

func (c *clockMsgImpl) GetVoterId() tt.ConsensusId {
	return c.voterId
}

func (c *clockMsgImpl) GetSignature() *bls.Signature {
	return c.signature
}

func (c *clockMsgImpl) equals(v *clockMsgImpl) bool {
	return bytes.Equal(c.signature.ToBytes(), v.signature.ToBytes()) &&
		c.epoch.Compare(v.GetEpoch()) == 0 &&
		c.voterId == v.GetVoterId()
}

func NewClockMsgImpl(e blocksn.Epoch, s bls.BlsSigner) tt.ClockMsg {
	return &clockMsgImpl{
		epoch:     e,
		signature: s.Sign(e.ToBytes()),
		voterId:   tt.ConsensusIdFromPubKey(s.GetPublicKey()),
	}
}
