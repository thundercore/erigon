package storage

import (
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/log/v3"
)

func sessionStopKey(session blocksn.Session) []byte {
	return append([]byte(kv.TTSessionStopBlock), ttCommon.Uint32ToBytes(uint32(session))...)
}

func blockSnKey(blockSn blocksn.BlockSn) []byte {
	return append([]byte(kv.TTBlock), blockSn.ToBytes()...)
}

func clockMsgNotaKey(e blocksn.Epoch) []byte {
	return append([]byte(kv.TTClockNotarization), e.ToBytes()...)
}

func notarizationKey(sn blocksn.BlockSn) []byte {
	return append(blockSnKey(sn), []byte(kv.TTNotarization)...)
}

func readSessionStopHeader(tx kv.Tx, session uint32) (*types.Header, blocksn.BlockSn) {
	var (
		hash   common.Hash
		number uint64

		data []byte
		err  error
	)

	if data, err = tx.GetOne(kv.TTConsensusInfo, sessionStopKey(blocksn.Session(session))); err != nil {
		logger.Error("failed to read session stop header", "session", session, "err", err)
		return nil, blocksn.BlockSn{}
	}

	if len(data) == 0 {
		return nil, blocksn.BlockSn{}
	}

	number, _, err = ttCommon.BytesToUint64(data)
	if err != nil {
		logger.Error("failed to deserialize data", "session", session, "data", data, "err", err)
		return nil, blocksn.BlockSn{}
	}

	hash, err = rawdb.ReadCanonicalHash(tx, number)
	if err != nil || hash == (common.Hash{}) {
		logger.Error("failed to read canonical hash", "session", session, "number", number, "err", err)
		return nil, blocksn.BlockSn{}
	}

	header := rawdb.ReadHeader(tx, hash, number)
	if session == 0 {
		if number == 0 {
			return header, blocksn.BlockSn{Epoch: blocksn.Epoch{}, S: 1}
		} else {
			return header, blocksn.NewBlockSn(0, 1, uint32(number))
		}
	} else {
		_, sn, err := blocksn.DecodeBlockSnFromNumber(header.Difficulty)
		if err != nil {
			logger.Error("failed to decode block sn from difficultiy", "session", session, "number", number, "difficulty", header.Difficulty.String(), "err", err)
			return nil, blocksn.BlockSn{}
		}
		return header, sn
	}
}

func writeEpochStatus(tx kv.RwTx, es *epochStatus) error {
	return tx.Put(kv.TTConsensusInfo, kv.TTEpochStatus, es.epoch.ToBytes())
}

func readEpochStatus(tx kv.Tx, marshaller tt.DataUnmarshaller) *epochStatus {
	var (
		e    blocksn.Epoch
		data []byte
		err  error
	)

	if data, err = tx.GetOne(kv.TTConsensusInfo, kv.TTEpochStatus); err != nil {
		log.Error("Failed to get tt epoch status", "err", err)
		return nil
	}

	if len(data) == 0 {
		return nil
	}

	e, _, err = blocksn.NewEpochFromBytes(data)
	if err != nil {
		logger.Error("failed to deserialize epoch", "data", data, "err", err)
		return nil
	}

	cn := ReadClockMsgNotarization(tx, marshaller, e)

	return &epochStatus{
		epoch:     e,
		clockNota: cn,
	}
}
