package storage

import (
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/committee"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/election"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/precompile"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/log/v3"
)

var (
	logger = log.New("package", "pala/storage")
)

func getElectionResult(statedb *state.IntraBlockState) *election.Result {
	raw := precompile.ElectionResults(statedb).ToSlice()

	if len(raw) == 0 {
		return nil
	}

	result := election.Result{}
	err := result.FromBytes(raw[0])
	if err != nil {
		return nil
	}
	return &result
}

func GetBlockCommitteeBySession(session uint32, config *chain.PalaConfig, tx kv.Tx) *committee.CommInfo {
	h, _ := readSessionStopHeader(tx, uint32(session-1))

	var (
		sdb    *state.IntraBlockState = nil
		reader *state.PlainState      = nil
	)

	bNum := uint64(0)
	blockNum := rawdb.ReadCurrentBlockNumber(tx)
	if blockNum != nil {
		bNum = *blockNum - 1
	}

	if h == nil {
		reader = state.NewPlainState(tx, bNum, make(map[common.Address][]common.CodeRecord))
	} else {
		reader = state.NewPlainState(tx, h.Number.Uint64(), make(map[common.Address][]common.CodeRecord))

	}
	sdb = state.New(reader)

	return GetBlockCommittee(h, sdb, config)
}

func GetBlockCommittee(header *types.Header, stateDb *state.IntraBlockState, config *chain.PalaConfig) *committee.CommInfo {
	blocksn := getBlockSnFromHeader(header, config)
	proposers := committee.ThunderCoreGenesisCommInfo.AccelInfo
	name := config.ProposerListName.GetValueHardforkAtSession(config.Hardforks, int64(blocksn.Epoch.Session))
	if name != "" {
		if p, ok := committee.AlterCommInfo[name]; ok {
			proposers = p.AccelInfo
		} else {
			debug.Bug("Missing consensus setting of proposer list name: %v", name)
		}
	}

	cInfo := &committee.CommInfo{}
	res := getElectionResult(stateDb)
	if res != nil {
		cInfo.AccelInfo = proposers
		cInfo.MemberInfo = res.Members
		return cInfo
	}
	if config.Common.Pala.FromGenesis {
		cInfo.AccelInfo = proposers
		cInfo.MemberInfo = append(cInfo.MemberInfo, committee.ThunderCoreGenesisCommInfo.MemberInfo...)
		return cInfo
	}

	return nil
}

func IsStopBlockHeader(header *types.Header, config *chain.PalaConfig) bool {
	number := header.Number.Uint64()

	if !config.IsPala(number) {
		return false
	}

	sessionOffset := header.Nonce.Uint64()
	session := blocksn.GetSessionFromDifficulty(header.Difficulty, header.Number, config)
	offset := config.ElectionStopBlockSessionOffset.GetValueHardforkAtSession(config.Hardforks, int64(session))

	return sessionOffset == uint64(offset)
}

func IsAfterStopBlockHeader(header *types.Header, includingStopBlock bool, config *chain.PalaConfig) bool {
	number := header.Number.Uint64()
	if !config.IsPala(header.Number.Uint64()) {
		logger.Warn("IsAfterStopBlockHeader called before pala hardfork", "number", number)
		return false
	}

	sessionOffset := header.Nonce.Uint64()
	session := blocksn.GetSessionFromDifficulty(header.Difficulty, header.Number, config)
	offset := uint64(config.ElectionStopBlockSessionOffset.GetValueHardforkAtSession(config.Hardforks, int64(session)))

	if includingStopBlock {
		return sessionOffset >= offset
	}
	return sessionOffset > offset
}

func WriteSessionStopBlockNumber(db kv.GetPut, session blocksn.Session, number uint64) error {
	return db.Put(kv.TTConsensusInfo, sessionStopKey(session), ttCommon.Uint64ToBytes(number))
}

func writeTTBlockMeta(db kv.GetPut, blockSn blocksn.BlockSn, header *types.Header) error {
	return db.Put(kv.TTConsensusInfo, blockSnKey(blockSn), header.Hash().Bytes())
}

func ReadFinalizedBlockSn(db kv.Getter) (blocksn.BlockSn, error) {
	data, err := db.GetOne(kv.TTConsensusInfo, kv.TTFinalizedSnKey)
	if err != nil {
		return blocksn.BlockSn{}, err
	}
	if len(data) == 0 {
		return blocksn.BlockSn{}, nil
	}
	blockSn, _, err := blocksn.NewBlockSnFromBytes(data)
	if err != nil {
		return blocksn.BlockSn{}, err
	}
	return blockSn, nil
}

func WriteFinalizedBlockSn(db kv.Putter, sn blocksn.BlockSn) error {
	return db.Put(kv.TTConsensusInfo, kv.TTFinalizedSnKey, sn.ToBytes())
}

func ReadFreshestNotarizedHeadSn(db kv.Getter) (blocksn.BlockSn, error) {
	data, err := db.GetOne(kv.TTConsensusInfo, kv.TTFreshestNotarizedHead)
	if err != nil {
		return blocksn.BlockSn{Epoch: blocksn.Epoch{}, S: 1}, err
	}
	if len(data) == 0 {
		return blocksn.BlockSn{Epoch: blocksn.Epoch{}, S: 1}, nil
	}
	blockSn, _, err := blocksn.NewBlockSnFromBytes(data)
	if err != nil {
		return blocksn.BlockSn{Epoch: blocksn.Epoch{}, S: 1}, err
	}
	return blockSn, nil
}

func WriteFreshestNotarization(db kv.Putter, sn blocksn.BlockSn) error {
	return db.Put(kv.TTConsensusInfo, kv.TTFreshestNotarizedHead, sn.ToBytes())
}

func ReadSessionStopBlockNumber(db kv.Getter, session blocksn.Session) (uint64, error) {
	data, err := db.GetOne(kv.TTConsensusInfo, sessionStopKey(session))
	if err != nil {
		return 0, err
	}
	// genesis block
	if len(data) == 0 {
		return 0, nil
	}
	number, _, err := ttCommon.BytesToUint64(data)
	if err != nil {
		return 0, err
	}
	return number, nil
}

func WriteNotarization(db kv.Putter, sn blocksn.BlockSn, nota tt.Notarization) error {
	return db.Put(kv.TTConsensusInfo, notarizationKey(sn), nota.GetBody())
}

func WriteClockMsgNotarization(db kv.Putter, cNota tt.ClockMsgNota) error {
	return db.Put(kv.TTConsensusInfo, clockMsgNotaKey(cNota.GetEpoch()), cNota.GetBody())
}

func ReadClockMsgNotarization(db kv.Getter, marshaller tt.DataUnmarshaller, e blocksn.Epoch) tt.ClockMsgNota {
	var (
		data []byte
		err  error
	)

	if data, err = db.GetOne(kv.TTConsensusInfo, clockMsgNotaKey(e)); err != nil {
		logger.Error("Read clock msg notarization failed", "epoch", e, "err", err)
		return nil
	}
	if len(data) == 0 {
		return nil
	}

	nota, _, err := marshaller.UnmarshalClockMsgNota(data)
	if err != nil {
		logger.Error("Unmarshal clock msg notarization failed", "epoch", e, "err", err)
		return nil
	}

	return nota
}

type BlockGetFunc func(kv.Tx, common.Hash, uint64) *types.Block

func ReadBlockFromBlockSnWithBlockGetter(tx kv.Tx, sn blocksn.BlockSn, config *chain.PalaConfig, blockGetter BlockGetFunc) tt.Block {
	if !sn.IsGenesis() && !sn.IsPala() && config.IsPala(uint64(sn.S)) {
		return nil
	}

	var (
		hash   common.Hash
		number uint64
		err    error
	)

	if sn.IsGenesis() {
		number = uint64(0)
		hash, err = rawdb.ReadCanonicalHash(tx, number)
	} else if !sn.IsPala() {
		// this means we are getting block from old chain (without difficulty encoded)
		// we consider all blocks that made before Pala are in BlockSn{0, 1, Block.Number}
		number = uint64(sn.S)
		hash, err = rawdb.ReadCanonicalHash(tx, number)
	} else {
		var (
			data []byte
		)

		if data, err = tx.GetOne(kv.TTConsensusInfo, blockSnKey(sn)); err != nil {
			return nil
		}

		numberPtr := rawdb.ReadHeaderNumber(tx, common.BytesToHash(data))
		if numberPtr == nil {
			return nil
		}
		number = *numberPtr
		hash = common.BytesToHash(data)
	}

	if err != nil {
		logger.Error("Read block from blocksn failed", "blocksn", sn, "err", err)
		return nil
	}

	block := blockGetter(tx, hash, number)
	if block == nil {
		logger.Error("Read block from hash and number", "blocksn", sn, "hash", hash, "number", number)
		return nil
	}

	return newBlock(block, config)
}

func ReadBlockFromBlockSn(tx kv.Tx, sn blocksn.BlockSn, config *chain.PalaConfig) tt.Block {
	return ReadBlockFromBlockSnWithBlockGetter(tx, sn, config, func(tx kv.Tx, hash common.Hash, number uint64) *types.Block {
		return rawdb.ReadBlock(tx, hash, number)
	})
}

func GetBlockByNumberWithBlockGetter(tx kv.Tx, number uint64, config *chain.PalaConfig, blockGetter BlockGetFunc) tt.Block {
	hash, err := rawdb.ReadCanonicalHash(tx, number)
	if err != nil {
		logger.Error("Read canonical hash failed", "number", number, "err", err)
		return nil
	}

	stopBlock := blockGetter(tx, hash, number)
	return newBlock(stopBlock, config)
}

func GetBlockByNumber(tx kv.Tx, number uint64, config *chain.PalaConfig) tt.Block {
	return GetBlockByNumberWithBlockGetter(tx, number, config, func(tx kv.Tx, hash common.Hash, number uint64) *types.Block {
		return rawdb.ReadBlock(tx, hash, number)
	})
}

func GetHeaderByNumber(tx kv.Getter, number uint64, config *chain.PalaConfig) tt.Header {
	hash, err := rawdb.ReadCanonicalHash(tx, number)
	if err != nil {
		logger.Error("Read canonical hash failed", "number", number, "err", err)
		return nil
	}
	header := rawdb.ReadHeader(tx, hash, number)
	if header == nil {
		return nil
	}

	return newHeader(header, config)
}

func ReadNotarization(tx kv.Tx, sn blocksn.BlockSn, config *chain.PalaConfig) tt.Notarization {
	data, err := tx.GetOne(kv.TTConsensusInfo, notarizationKey(sn))
	if err != nil {
		return nil
	}

	unmarshaller := NewDataUnmarshaller(config)
	nota, _, err := unmarshaller.UnmarshalNotarization(data)
	if err != nil {
		return nil
	}
	return nota
}

func AddNotarization(tx kv.RwTx, nota tt.Notarization, config *chain.PalaConfig) (blocksn.BlockSn, blocksn.BlockSn, error) {
	var freshestExt, finalExt blocksn.BlockSn

	sn := nota.GetBlockSn()
	oldFreshest, err := ReadFreshestNotarizedHeadSn(tx)
	if err != nil {
		return blocksn.BlockSn{}, blocksn.BlockSn{}, err
	}
	if err := WriteNotarization(tx, sn, nota); err != nil {
		return blocksn.BlockSn{}, blocksn.BlockSn{}, err
	}

	k := config.K.GetValueHardforkAtSession(config.Hardforks, int64(sn.Epoch.Session))

	if sn.Compare(oldFreshest) > 0 {
		if err := WriteFreshestNotarization(tx, sn); err != nil {
			return blocksn.BlockSn{}, blocksn.BlockSn{}, err
		}
		freshestExt = sn

		if int64(sn.S) > k {
			candidate := sn
			candidate.S -= uint32(k)
			oldFinal, err := ReadFinalizedBlockSn(tx)
			if err != nil {
				return blocksn.BlockSn{}, blocksn.BlockSn{}, err
			}

			if candidate.Compare(oldFinal) > 0 {
				if err := WriteFinalizedBlockSn(tx, candidate); err != nil {
					return blocksn.BlockSn{}, blocksn.BlockSn{}, err
				}
				finalExt = candidate
			}
		}
	}

	return freshestExt, finalExt, nil
}

func GetLatestFinalizedStopBlock(tx kv.RwTx, config *chain.PalaConfig, blockGetter BlockGetFunc) tt.Block {
	sn, err := ReadFinalizedBlockSn(tx)
	if err != nil {
		log.Error("Failed to read finalized block sn", "err", err)
		return nil
	}
	unmarshaller := NewDataUnmarshaller(config)
	es := updateEpochStatusIfNotExisted(tx, unmarshaller)
	for session := es.epoch.Session; session > 0; session-- {
		if header, stopSn := readSessionStopHeader(tx, uint32(session)); header != nil {
			if sn.Compare(stopSn) >= 0 {
				return ReadBlockFromBlockSnWithBlockGetter(tx, stopSn, config, blockGetter)
			}
		}
	}
	return nil
}
