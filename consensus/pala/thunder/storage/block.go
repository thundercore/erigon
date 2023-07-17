package storage

import (
	"fmt"

	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/rlp"
)

type blockSnCache struct {
	parentSn blocksn.BlockSn
	sn       blocksn.BlockSn
}

type blockImpl struct {
	cache *blockSnCache
	B     *types.Block
}

func (b *blockImpl) GetType() tt.Type { return tt.TypeBlock }

// GetBlockSn() and GetParentBlockSn() have a hardfork behavior,
// we consider all blocks that made before Pala are in BlockSn{0, 1, Block.Number},
// and the Genesis BlockSn is {0, 0, 1}
// (we reserve {0, 0, 0} for empty BlockSn)
// That makes us able to hardfork from a chain which doesn't have BlockSn.
func (cache *blockSnCache) updateFromBlockNumber(number uint64) {
	if number == 0 {
		cache.parentSn = blocksn.BlockSn{}
		cache.sn = blocksn.GetGenesisBlockSn()
	} else if number == 1 {
		cache.parentSn = blocksn.GetGenesisBlockSn()
		cache.sn = blocksn.NewBlockSn(0, 1, uint32(number))
	} else {
		cache.parentSn = blocksn.NewBlockSn(0, 1, uint32(number-1))
		cache.sn = blocksn.NewBlockSn(0, 1, uint32(number))
	}
}

func (b *blockImpl) GetBlockSn() blocksn.BlockSn {
	if b.cache == nil {
		debug.Bug("Cannot decode BlockSn from Difficulty")

	}
	return b.cache.sn
}

func (b *blockImpl) GetParentBlockSn() blocksn.BlockSn {
	if b.cache == nil {
		debug.Bug("Cannot decode BlockSn from Difficulty")

	}

	return b.cache.parentSn
}

func (b *blockImpl) GetDebugString() string { return b.String() }
func (b *blockImpl) GetBody() []byte {
	data, err := rlp.EncodeToBytes(b.B)
	if err != nil {
		return nil
	}

	return data
}

func (b *blockImpl) GetHash() tt.Hash {
	return tt.Hash(b.B.Hash())
}

func (b *blockImpl) GetParentHash() tt.Hash {
	return tt.Hash(b.B.ParentHash())
}

func (b *blockImpl) GetBodyString() string {
	return fmt.Sprintf("(\nBlockSn: %s,\nParentBlockSn: %s,\nHeight: %d,\nNumber Of Transactions: %d\n)", b.GetBlockSn(), b.GetParentBlockSn(), b.B.NumberU64(), len(b.B.Transactions()))
}

func (b *blockImpl) GetNumber() uint64 {
	return b.B.NumberU64()
}

func (b *blockImpl) String() string {
	return fmt.Sprintf("(%s,%x)", b.GetBlockSn(), b.B.Hash())
}

func (b *blockImpl) ImplementsBlock() {

}

func newBlock(b *types.Block, config *chain.PalaConfig) tt.Block {
	cache := &blockSnCache{}
	var err error

	if config.IsPala(b.Number().Uint64()) {
		if cache.parentSn, cache.sn, err = blocksn.DecodeBlockSnFromNumber(b.Difficulty()); err != nil {
			debug.Bug("Cannot decode BlockSn from Difficulty")
		}
	} else {
		cache.updateFromBlockNumber(b.NumberU64())
	}

	bi := &blockImpl{
		cache: cache,
		B:     b,
	}

	return bi
}

func (b *blockImpl) equals(other *blockImpl) bool {
	return b.GetParentBlockSn().Compare(other.GetParentBlockSn()) == 0 &&
		b.GetBlockSn().Compare(other.GetBlockSn()) == 0 &&
		b.B.Hash() == other.B.Hash()
}

// TODO(sonic): put this in blockImpl
type headerImpl struct {
	cache *blockSnCache
	H     *types.Header
}

func (h *headerImpl) ImplementsHeader() {}

func (h *headerImpl) GetType() tt.Type { return tt.TypeHeader }

func (h *headerImpl) GetBlockSn() blocksn.BlockSn {
	if h.cache == nil {
		debug.Bug("Cannot decode BlockSn from Difficulty")

	}
	return h.cache.sn
}

func (h *headerImpl) GetParentBlockSn() blocksn.BlockSn {
	if h.cache == nil {
		debug.Bug("Cannot decode BlockSn from Difficulty")

	}
	return h.cache.parentSn
}

func (h *headerImpl) String() string {
	return fmt.Sprintf("(%s,%x)", h.GetBlockSn(), h.H.Hash())
}

func (h *headerImpl) GetDebugString() string {
	return h.String()
}

func (h *headerImpl) GetBody() []byte {
	data, err := rlp.EncodeToBytes(h.H)
	if err != nil {
		return nil
	}

	return data
}

func (h *headerImpl) GetHash() tt.Hash {
	return tt.Hash(h.H.Hash())
}

func (h *headerImpl) GetNumber() uint64 {
	return h.H.Number.Uint64()
}

func newHeader(h *types.Header, config *chain.PalaConfig) tt.Header {
	cache := &blockSnCache{}
	var err error

	if config.IsPala(h.Number.Uint64()) {
		if cache.parentSn, cache.sn, err = blocksn.DecodeBlockSnFromNumber(h.Difficulty); err != nil {
			debug.Bug("Cannot decode BlockSn from Difficulty")
		}
	} else {
		cache.updateFromBlockNumber(h.Number.Uint64())
	}

	hi := &headerImpl{
		cache: cache,
		H:     h,
	}

	return hi
}

// BlockImplDecoder can decode notarizations and clock message notarization via the DataUnmarshaller
type BlockImplDecoder struct {
	unmarshaller tt.DataUnmarshaller
}

func NewBlockImplDecoder(
	unmarshaller tt.DataUnmarshaller,
) *BlockImplDecoder {
	return &BlockImplDecoder{
		unmarshaller: unmarshaller,
	}
}

func (d *BlockImplDecoder) getConsensusInfo(block tt.Block, config *chain.PalaConfig) (*ConsensusInfo, error) {
	sn := block.GetBlockSn()
	ethBlock := block.(*blockImpl).B

	session := blocksn.GetSessionFromDifficulty(ethBlock.Header().Difficulty, ethBlock.Header().Number, config)

	if config.IsConsensusInfoInHeader.GetValueHardforkAtSession(config.Hardforks, int64(session)) {
		return bytesToConsensusInfo(ethBlock.Extra(), d.unmarshaller)
	}

	k := uint32(config.K.GetValueHardforkAtSession(config.Hardforks, int64(session)))

	txs := block.(*blockImpl).B.Transactions()
	var tx types.Transaction

	if block.GetParentBlockSn().IsPala() {
		if sn.S == 1 || sn.S > k {
			tx = txs[len(txs)-1]
		}
	}

	if tx == nil {
		return nil, fmt.Errorf("cannot find consensus info in %s", block.GetBlockSn())
	}

	return bytesToConsensusInfo(tx.GetData(), d.unmarshaller)
}

func (d *BlockImplDecoder) PrehandleBlock(block tt.Block) {
}

func (d *BlockImplDecoder) ToRawBlock(header []byte, body []byte) ([]byte, error) {
	b := struct {
		Transactions rlp.RawValue
		Uncles       rlp.RawValue
	}{}
	if err := rlp.DecodeBytes(body, &b); err != nil {
		return nil, err
	}

	type extBlock struct {
		Header       rlp.RawValue
		Transactions rlp.RawValue
		Uncles       rlp.RawValue
	}

	data, err := rlp.EncodeToBytes(&extBlock{
		Header:       header,
		Transactions: b.Transactions,
		Uncles:       b.Uncles,
	})
	return data, err
}

func (d *BlockImplDecoder) GetNotarizations(block tt.Block, config *chain.PalaConfig) []tt.Notarization {
	if ci, err := d.getConsensusInfo(block, config); err == nil {
		return ci.Notas
	}

	return nil
}

func (d *BlockImplDecoder) GetClockMsgNota(block tt.Block, config *chain.PalaConfig) tt.ClockMsgNota {
	if ci, err := d.getConsensusInfo(block, config); err == nil {
		return ci.ClockNota
	}

	return nil
}

type ConsensusInfo struct {
	Notas     []tt.Notarization
	ClockNota tt.ClockMsgNota
}

func (ci *ConsensusInfo) ToBytes() []byte {
	l := uint32(len(ci.Notas))
	ret := ttCommon.Uint32ToBytes(l)

	for _, nota := range ci.Notas {
		ret = append(ret, nota.GetBody()...)
	}

	if ci.ClockNota != nil {
		ret = append(ret, ci.ClockNota.GetBody()...)
	}

	return ret
}

func bytesToConsensusInfo(data []byte, unmarshaller tt.DataUnmarshaller) (*ConsensusInfo, error) {
	length, data, err := ttCommon.BytesToUint32(data)
	if err != nil {
		return nil, err
	}
	var (
		ret = &ConsensusInfo{
			Notas: make([]tt.Notarization, length),
		}
	)

	for i := uint32(0); i < length; i++ {
		ret.Notas[i], data, err = unmarshaller.UnmarshalNotarization(data)
		if err != nil {
			return ret, err
		}
	}

	if len(data) != 0 {
		ret.ClockNota, _, err = unmarshaller.UnmarshalClockMsgNota(data)
		if err != nil {
			return ret, err
		}
	}

	return ret, nil
}
