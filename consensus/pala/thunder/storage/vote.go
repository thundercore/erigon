package storage

import (
	"bytes"
	"fmt"

	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/bls"
	ttC "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
)

type voteImpl struct {
	blockHash tt.Hash
	sn        blocksn.BlockSn
	signature *bls.Signature
	voterId   tt.ConsensusId
}

func (v *voteImpl) ImplementsVote() {
}

func (v *voteImpl) GetType() tt.Type {
	return tt.TypeVote
}

func (v *voteImpl) GetBody() []byte {
	bytes := ttC.StringToBytes(string(v.voterId))
	bytes = append(bytes, v.signature.ToBytes()...)
	bytes = append(bytes, v.sn.ToBytes()...)
	return append(bytes, v.blockHash.Bytes()...)
}

func (v *voteImpl) GetBlockSn() blocksn.BlockSn {
	return v.sn
}

func (v *voteImpl) GetDebugString() string {
	return v.String()
}

func (v *voteImpl) String() string {
	return fmt.Sprintf("voteImpl{%s,%s}", v.sn, v.voterId)
}

func (v *voteImpl) GetVoterId() tt.ConsensusId {
	return v.voterId
}

func (v *voteImpl) GetBlockHash() tt.Hash {
	return v.blockHash
}

func (v *voteImpl) GetSignature() *bls.Signature {
	return v.signature
}

func (v *voteImpl) equals(s *voteImpl) bool {
	return bytes.Equal(v.signature.ToBytes(), s.signature.ToBytes()) &&
		v.blockHash == s.blockHash &&
		v.sn.Compare(s.GetBlockSn()) == 0 &&
		v.voterId == s.GetVoterId()
}

func NewVoteImpl(p tt.Proposal, s bls.BlsSigner) tt.Vote {
	return &voteImpl{
		blockHash: p.GetBlock().GetHash(),
		sn:        p.GetBlockSn(),
		signature: s.Sign(p.GetBlock().GetHash().Bytes()),
		voterId:   tt.ConsensusIdFromPubKey(s.GetPublicKey()),
	}
}
