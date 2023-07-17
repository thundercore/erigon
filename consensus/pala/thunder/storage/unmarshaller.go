package storage

import (
	"fmt"

	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/bls"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	ttTypes "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/rlp"
	"github.com/ledgerwatch/log/v3"
)

const blsSigBytes = 256 / 8 * 2

func bytesToBlsSig(bytes []byte) (*bls.Signature, []byte, error) {
	if len(bytes) < blsSigBytes {
		return nil, nil, fmt.Errorf("invalid sig bytes: len(bytes) = %d < %d", len(bytes), blsSigBytes)
	}

	if sig, err := bls.SignatureFromBytes(bytes[:blsSigBytes]); err != nil {
		return nil, nil, err
	} else {
		return sig, bytes[blsSigBytes:], nil
	}
}

func bytesToHash(bytes []byte) (ttTypes.Hash, []byte, error) {
	if len(bytes) < ttCommon.HashLength {
		return ttTypes.Hash{}, nil, fmt.Errorf("invalid hash bytes: len(bytes) = %d < %d", len(bytes), ttCommon.HashLength)
	}
	return ttTypes.BytesToHash(bytes[:ttCommon.HashLength]), bytes[ttCommon.HashLength:], nil
}

type DataUnmarshallerImpl struct {
	Config *chain.PalaConfig
}

func NewDataUnmarshaller(config *chain.PalaConfig) ttTypes.DataUnmarshaller {
	return &DataUnmarshallerImpl{Config: config}
}

func (d *DataUnmarshallerImpl) UnmarshalBlock(bytes []byte) (ttTypes.Block, []byte, error) {
	log.Trace("UnmarshalBlock")
	if d.Config == nil {
		debug.Bug("Need config to decode block here")
	}

	b := new(types.Block)
	if err := rlp.DecodeBytes(bytes, b); err != nil {
		return nil, bytes, err
	}

	bi := newBlock(b, d.Config)

	return bi, []byte{}, nil
}

func (d *DataUnmarshallerImpl) UnmarshalProposal(bytes []byte) (ttTypes.Proposal, []byte, error) {
	log.Trace("UnmarshalProposal")
	idStr, bytes, err := ttCommon.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	id := ttTypes.ConsensusId(idStr)

	sig, bytes, err := bytesToBlsSig(bytes)
	if err != nil {
		return nil, nil, err
	}

	if block, bytes, err := d.UnmarshalBlock(bytes); err != nil {
		return nil, nil, err
	} else {
		return &proposalImpl{block: block, proposerId: id, signature: sig}, bytes, nil
	}
}

func (d *DataUnmarshallerImpl) UnmarshalVote(bytes []byte) (ttTypes.Vote, []byte, error) {
	log.Trace("UnmarshalVote")
	idStr, bytes, err := ttCommon.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	id := ttTypes.ConsensusId(idStr)

	sig, bytes, err := bytesToBlsSig(bytes)
	if err != nil {
		return nil, nil, err
	}

	sn, bytes, err := blocksn.NewBlockSnFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}

	if hash, bytes, err := bytesToHash(bytes); err != nil {
		return nil, nil, err
	} else {
		return &voteImpl{voterId: id, sn: sn, signature: sig, blockHash: hash}, bytes, nil
	}
}

// | blocksn  |  common.Hash | bls.sig 256 / 8 * 2 | pindex (int16) | nvote (int16) |  nmissingVote(int16) |  missvote * n (int16 * n)
func (d *DataUnmarshallerImpl) UnmarshalNotarization(bytes []byte) (ttTypes.Notarization, []byte, error) {
	logger.Trace("UnmarshalNotarization")
	missingVoterIdxs := make([]uint16, 0)

	sn, bytes, err := blocksn.NewBlockSnFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}

	hash, bytes, err := bytesToHash(bytes)
	if err != nil {
		return nil, nil, err
	}

	sig, bytes, err := bytesToBlsSig(bytes)
	if err != nil {
		return nil, nil, err
	}

	pIdx, bytes, err := ttCommon.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	nVote, bytes, err := ttCommon.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	nMissingVote, bytes, err := ttCommon.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < int(nMissingVote); i++ {
		var v uint16
		var err error
		v, bytes, err = ttCommon.BytesToUint16(bytes)
		if err != nil {
			return nil, nil, err
		}
		missingVoterIdxs = append(missingVoterIdxs, v)
	}
	return &notarizationImpl{
		sn:               sn,
		aggSig:           sig,
		blockHash:        hash,
		proposerIdx:      pIdx,
		nVote:            nVote,
		missingVoterIdxs: missingVoterIdxs,
	}, bytes, nil
}

func (d *DataUnmarshallerImpl) UnmarshalClockMsg(bytes []byte) (ttTypes.ClockMsg, []byte, error) {
	logger.Debug("UnmarshalClockMsg")
	idStr, bytes, err := ttCommon.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	id := ttTypes.ConsensusId(idStr)

	sig, bytes, err := bytesToBlsSig(bytes)
	if err != nil {
		return nil, nil, err
	}

	if e, bytes, err := blocksn.NewEpochFromBytes(bytes); err != nil {
		return nil, nil, err
	} else {
		return &clockMsgImpl{voterId: id, signature: sig, epoch: e}, bytes, nil
	}
}

// | epoch | bls.sig 256 / 8 * 2 | pindex (int16) | nvote (int16) |  nmissingVote(int16) |  missvote * n (int16 * n) |
func (d *DataUnmarshallerImpl) UnmarshalClockMsgNota(bytes []byte) (ttTypes.ClockMsgNota, []byte, error) {
	logger.Trace("UnmarshalClockMsgNota")
	missingVoterIdxs := make([]uint16, 0)

	e, bytes, err := blocksn.NewEpochFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}

	sig, bytes, err := bytesToBlsSig(bytes)
	if err != nil {
		return nil, nil, err
	}

	pIdx, bytes, err := ttCommon.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	nVote, bytes, err := ttCommon.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	nMissingVote, bytes, err := ttCommon.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < int(nMissingVote); i++ {
		var v uint16
		var err error
		v, bytes, err = ttCommon.BytesToUint16(bytes)
		if err != nil {
			return nil, nil, err
		}
		missingVoterIdxs = append(missingVoterIdxs, v)
	}
	return &clockMsgNotaImpl{
		epoch:            e,
		aggSig:           sig,
		proposerIdx:      pIdx,
		nVote:            nVote,
		missingVoterIdxs: missingVoterIdxs,
	}, bytes, nil
}
