package storage

import (
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/log/v3"
)

var (
	crLog = log.New("package", "pala/chain_reader")
)

type ChainReader struct {
	tx           kv.Tx
	config       *chain.PalaConfig
	genesisBlock *types.Block
}

func NewChainReader(tx kv.Tx, config *chain.PalaConfig) *ChainReader {
	return &ChainReader{
		tx:     tx,
		config: config,
	}
}

func (c *ChainReader) ContainsBlock(s blocksn.BlockSn) bool {
	return c.GetBlock(s) != nil
}

func (c *ChainReader) GetBlock(s blocksn.BlockSn) tt.Block {
	return ReadBlockFromBlockSn(c.tx, s, c.config)
}

func (c *ChainReader) GetGenesisBlock() tt.Block {
	return newBlock(c.genesisBlock, c.config)
}

func (c *ChainReader) GetNotarization(sn blocksn.BlockSn) tt.Notarization {
	return ReadNotarization(c.tx, sn, c.config)
}

func (c *ChainReader) GetFreshestNotarizedHead() tt.Block {
	sn, err := ReadFreshestNotarizedHeadSn(c.tx)
	if err != nil {
		crLog.Error("Failed to read freshest nota head sn", "err", err)
		return nil
	}

	blk := ReadBlockFromBlockSn(c.tx, sn, c.config)
	if blk == nil {
		crLog.Crit("Failed to read freshest nota head block", "sn", sn)
	}

	return blk
}

func (c *ChainReader) GetFinalizedHead() tt.Block {
	sn, err := ReadFinalizedBlockSn(c.tx)
	if err != nil {
		crLog.Error("Failed to read finalized head sn", "err", err)
		return nil
	}

	blk := ReadBlockFromBlockSn(c.tx, sn, c.config)
	if blk == nil {
		crLog.Crit("Failed to read finalized head block", "sn", sn)
	}

	return blk
}

func (c *ChainReader) DecodeBlock(b tt.Block) ([]tt.Notarization, tt.ClockMsgNota) {
	unmarshaller := NewDataUnmarshaller(c.config)
	decoder := NewBlockImplDecoder(unmarshaller)

	return decoder.GetNotarizations(b, c.config), decoder.GetClockMsgNota(b, c.config)
}

// TODO: before impl proposer, we don't know if this function is needed
func (c *ChainReader) IsCreatingBlock() bool {
	return false
}

// TODO: before impl consensus node, we don't know if this function is needed
func (c *ChainReader) GetProposerAddresses(session blocksn.Session) map[tt.ConsensusId]string {
	return make(map[tt.ConsensusId]string)
}
