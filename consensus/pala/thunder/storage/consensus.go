package storage

import (
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/turbo/services"
)

type HandleThunderConsensusFunc func(header *types.Header, config *chain.PalaConfig) error

func getBlockSnFromHeader(header *types.Header, config *chain.PalaConfig) blocksn.BlockSn {
	return blocksn.GetBlockSnFromDifficulty(header.Difficulty, header.Number, config)
}

func handleStopBlock(header *types.Header, db kv.GetPut, reader services.HeaderReader, config *chain.PalaConfig) error {
	if header == nil {
		return nil
	}

	parentSn, blockSn, err := blocksn.DecodeBlockSnFromNumber(header.Difficulty)
	if err != nil {
		return err
	}

	if IsStopBlockHeader(header, config) {
		WriteSessionStopBlockNumber(db, blockSn.Epoch.Session, header.Number.Uint64())
	}

	if parentSn.Epoch.Session == 0 {
		num, err := ReadSessionStopBlockNumber(db, parentSn.Epoch.Session)
		if err != nil {
			return err
		}
		sn := blocksn.NewBlockSn(0, 1, uint32(num))

		if num == 0 {
			sn.Epoch.E = 0
		}

		WriteSessionStopBlockNumber(db, parentSn.Epoch.Session, header.Number.Uint64()-1)
	}

	return nil
}

func NewHandleThunderConsensusFunc(db kv.GetPut, reader services.HeaderReader) HandleThunderConsensusFunc {
	return func(header *types.Header, config *chain.PalaConfig) error {
		sn := getBlockSnFromHeader(header, config)

		if err := handleStopBlock(header, db, reader, config); err != nil {
			return err
		}
		if err := writeTTBlockMeta(db, sn, header); err != nil {
			return err
		}
		return nil
	}
}
