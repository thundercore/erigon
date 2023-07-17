package storage

import (
	"bytes"
	"fmt"

	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/bls"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
)

type proposalImpl struct {
	block      tt.Block
	signature  *bls.Signature
	proposerId tt.ConsensusId
}

func (p *proposalImpl) ImplementsProposal() {
}

func (p *proposalImpl) GetType() tt.Type {
	return tt.TypeProposal
}

func (p *proposalImpl) GetBody() []byte {
	bytes := ttCommon.StringToBytes(string(p.proposerId))
	bytes = append(bytes, p.signature.ToBytes()...)
	return append(bytes, p.block.GetBody()...)
}

func (p *proposalImpl) GetBlockSn() blocksn.BlockSn {
	return p.block.GetBlockSn()
}

func (p *proposalImpl) GetDebugString() string {
	return p.String()
}

func (p *proposalImpl) String() string {
	return fmt.Sprintf("proposalImpl{%s,%s}", p.block.GetBlockSn(), p.proposerId)
}

func (p *proposalImpl) GetBlock() tt.Block {
	return p.block
}

func (p *proposalImpl) GetProposerId() tt.ConsensusId {
	return p.proposerId
}

func (p *proposalImpl) equals(v *proposalImpl) bool {
	return bytes.Equal(p.signature.ToBytes(), v.signature.ToBytes()) &&
		p.GetBlockSn() == v.GetBlockSn() &&
		p.GetBlock().GetHash() == v.GetBlock().GetHash() &&
		p.proposerId == v.GetProposerId()
}

func NewProposalImpl(b tt.Block, s bls.BlsSigner) tt.Proposal {
	return &proposalImpl{
		block:      b,
		signature:  s.Sign(b.GetHash().Bytes()),
		proposerId: tt.ConsensusIdFromPubKey(s.GetPublicKey()),
	}
}
