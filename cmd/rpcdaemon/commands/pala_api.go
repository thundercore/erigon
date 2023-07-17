package commands

import (
	"context"
	"fmt"
	"math/big"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon/common/hexutil"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/committee"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/precompile"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/reward"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/storage"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/rpc"
	"github.com/ledgerwatch/erigon/turbo/transactions"
	"github.com/ledgerwatch/log/v3"
)

type PalaAPI interface {
	GetTotalFeeBurned(num *rpc.BlockNumber) (*NumericRpcResponse, error)
	GetTotalSupply(num *rpc.BlockNumber) (*NumericRpcResponse, error)
	GetTotalInflation(num *rpc.BlockNumber) (*NumericRpcResponse, error)
	GetReward(num *rpc.BlockNumber) (*reward.Results, error)
	GetConsensusNodesInfo(num *rpc.BlockNumber) (*committee.CommInfo, error)
	GetBlockSnByNumber(num *rpc.BlockNumber) (*string, error)
	GetNumberByBlockSn(session, epoch, s uint32) (*rpc.BlockNumber, error)
	GetBlockInfo(number *rpc.BlockNumber) (*BlockInfoResponse, error)
	GetTtTransfersByBlockNumber(num *rpc.BlockNumber) ([]TtTransferWithHash, error)
}

type PalaImpl struct {
	*BaseAPI
	db         kv.RoDB
	config     *chain.Config
	ttBlockLRU *lru.Cache[uint64, []TtTransferWithHash]
}

func NewPalaAPI(base *BaseAPI, db kv.RoDB, config *chain.Config) *PalaImpl {
	lruSize := 128

	ttBlockLRU, err := lru.New[uint64, []TtTransferWithHash](lruSize)
	if err != nil {
		panic(err)
	}

	return &PalaImpl{
		BaseAPI:    base,
		db:         db,
		config:     config,
		ttBlockLRU: ttBlockLRU,
	}
}

type NumericRpcResponse struct {
	BlockNumber *big.Int
	Result      *big.Int
}

func (p *PalaImpl) GetTotalFeeBurned(num *rpc.BlockNumber) (*NumericRpcResponse, error) {
	var block *types.Block

	tx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if num == nil || *num == rpc.LatestBlockNumber {
		block = rawdb.ReadCurrentBlock(tx)
	} else {
		block, err = rawdb.ReadBlockByNumber(tx, uint64(*num))
		if err != nil {
			return nil, err
		}
	}

	reader := state.NewPlainState(tx, block.Number().Uint64(), make(map[common.Address][]common.CodeRecord))
	ibs := state.New(reader)

	feeBurned := reward.GetTotalFeeBurned(ibs)

	return &NumericRpcResponse{block.Number(), feeBurned}, nil
}

func (p *PalaImpl) GetTotalSupply(num *rpc.BlockNumber) (*NumericRpcResponse, error) {
	var block *types.Block

	tx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if num == nil || *num == rpc.LatestBlockNumber {
		block = rawdb.ReadCurrentBlock(tx)
	} else {
		block, err = rawdb.ReadBlockByNumber(tx, uint64(*num))
		if err != nil {
			return nil, err
		}
	}

	reader := state.NewPlainState(tx, block.Number().Uint64(), make(map[common.Address][]common.CodeRecord))
	ibs := state.New(reader)

	feeBurned := reward.GetTotalFeeBurned(ibs)
	inflation := reward.GetTotalInflation(ibs)
	supply := new(big.Int).Add(p.config.Pala.Common.Chain.InitialSupplyInBig, inflation)
	supply = supply.Sub(supply, feeBurned)

	return &NumericRpcResponse{block.Number(), supply}, nil
}

func (p *PalaImpl) GetTotalInflation(num *rpc.BlockNumber) (*NumericRpcResponse, error) {
	var block *types.Block

	tx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if num == nil || *num == rpc.LatestBlockNumber {
		block = rawdb.ReadCurrentBlock(tx)
	} else {
		block, err = rawdb.ReadBlockByNumber(tx, uint64(*num))
		if err != nil {
			return nil, err
		}
	}

	reader := state.NewPlainState(tx, block.Number().Uint64(), make(map[common.Address][]common.CodeRecord))
	ibs := state.New(reader)

	inflation := reward.GetTotalInflation(ibs)

	return &NumericRpcResponse{block.Number(), inflation}, nil
}

func (p *PalaImpl) GetReward(num *rpc.BlockNumber) (*reward.Results, error) {
	if num == nil || num.Int64() < rpc.LatestBlockNumber.Int64() {
		return nil, fmt.Errorf("invalid block number")
	}

	tx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	blockNum := uint64(num.Int64())
	if *num == rpc.LatestBlockNumber {
		bn := rawdb.ReadCurrentBlockNumber(tx)
		if bn == nil {
			return nil, fmt.Errorf("invalid block number")
		}
		blockNum = *bn
	}

	hash, err := rawdb.ReadCanonicalHash(tx, blockNum)
	if err != nil {
		log.Error("Read canonical hash failed", "number", blockNum, "err", err)
		return nil, fmt.Errorf("read canonical hash failed")
	}

	header := rawdb.ReadHeader(tx, hash, blockNum)
	reader := state.NewPlainState(tx, header.Number.Uint64(), make(map[common.Address][]common.CodeRecord))
	ibs := state.New(reader)

	if !storage.IsStopBlockHeader(header, p.config.Pala) {
		return nil, fmt.Errorf("not stop block")
	}

	commInfo := storage.GetBlockCommittee(header, ibs, p.config.Pala)
	return reward.GetPreviousDistribution(commInfo, ibs)
}

func (p *PalaImpl) GetConsensusNodesInfo(num *rpc.BlockNumber) (*committee.CommInfo, error) {
	if num == nil || num.Int64() < rpc.LatestBlockNumber.Int64() {
		return nil, fmt.Errorf("invalid block number")
	}

	tx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	blockNum := uint64(num.Int64())
	if *num == rpc.LatestBlockNumber {
		bn := rawdb.ReadCurrentBlockNumber(tx)
		if bn == nil {
			return nil, fmt.Errorf("invalid block number")
		}
		blockNum = *bn
	}

	hash, err := rawdb.ReadCanonicalHash(tx, blockNum)
	if err != nil {
		log.Error("Read canonical hash failed", "number", blockNum, "err", err)
		return nil, fmt.Errorf("read canonical hash failed")
	}

	header := rawdb.ReadHeader(tx, hash, blockNum)
	reader := state.NewPlainState(tx, header.Number.Uint64(), make(map[common.Address][]common.CodeRecord))
	ibs := state.New(reader)

	return storage.GetBlockCommittee(header, ibs, p.config.Pala), nil
}

func (p *PalaImpl) GetBlockSnByNumber(num *rpc.BlockNumber) (*string, error) {
	if num == nil || num.Int64() < rpc.LatestBlockNumber.Int64() {
		return nil, fmt.Errorf("invalid block number")
	}

	tx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	blockNum := uint64(num.Int64())
	if *num == rpc.LatestBlockNumber {
		bn := rawdb.ReadCurrentBlockNumber(tx)
		if bn == nil {
			return nil, fmt.Errorf("invalid block number")
		}
		blockNum = *bn
	}

	header := storage.GetHeaderByNumber(tx, blockNum, p.config.Pala)
	if header == nil {
		return nil, fmt.Errorf("failed to get header for height=%d", blockNum)
	}

	var blockSn *string = nil
	sn := header.GetBlockSn().String()
	blockSn = &sn

	return blockSn, nil
}

func (p *PalaImpl) GetNumberByBlockSn(session, epoch, s uint32) (*rpc.BlockNumber, error) {
	tx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	sn := blocksn.NewBlockSn(session, epoch, s)
	block := storage.ReadBlockFromBlockSnWithBlockGetter(tx, sn, p.config.Pala, makeBlockGetterFunc(p.BaseAPI))
	if block == nil {
		return nil, fmt.Errorf("failed to get block for %s", sn.String())
	}

	bn := rpc.BlockNumber(block.GetNumber())
	return &bn, nil
}

type BlockStatus struct {
	BlockSn string
	Height  uint64
}

type SessionStatus struct {
	StartBlock BlockStatus
	StopBlock  BlockStatus
	EndBlock   BlockStatus
	K          uint32
}

func (p *PalaImpl) GetSessionStatus(session uint32) (*SessionStatus, error) {
	tx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}

	defer tx.Rollback()

	stopOffSet := p.config.Pala.ElectionStopBlockSessionOffset.GetValueHardforkAtSession(p.config.Pala.Hardforks, int64(session))

	resp := &SessionStatus{}
	resp.K = uint32(p.config.Pala.K.GetValueHardforkAtSession(p.config.Pala.Hardforks, int64(session)))

	startBlockSn := blocksn.NewBlockSn(session, 1, 1)
	startBlock := storage.ReadBlockFromBlockSnWithBlockGetter(tx, startBlockSn, p.config.Pala, makeBlockGetterFunc(p.BaseAPI))
	if startBlock == nil {
		return nil, fmt.Errorf("start block not found at %v", session)
	}

	resp.StartBlock = BlockStatus{
		BlockSn: startBlockSn.String(),
		Height:  startBlock.GetNumber(),
	}

	nextSessionBlockSn := blocksn.NewBlockSn(session+1, 1, 1)
	nextSessionBlock := storage.ReadBlockFromBlockSnWithBlockGetter(tx, nextSessionBlockSn, p.config.Pala, makeBlockGetterFunc(p.BaseAPI))

	if nextSessionBlock == nil {
		finalizedBlockSn, err := storage.ReadFinalizedBlockSn(tx)
		if err != nil {
			return nil, err
		}

		finalizedHead := storage.ReadBlockFromBlockSnWithBlockGetter(tx, finalizedBlockSn, p.config.Pala, makeBlockGetterFunc(p.BaseAPI))
		if finalizedHead == nil {
			return nil, fmt.Errorf("finalized block not found at %v", finalizedBlockSn)
		}

		resp.EndBlock = BlockStatus{
			BlockSn: finalizedBlockSn.String(),
			Height:  finalizedHead.GetNumber(),
		}

		return resp, nil
	}

	resp.EndBlock = BlockStatus{
		BlockSn: nextSessionBlockSn.String(),
		Height:  nextSessionBlock.GetNumber(),
	}

	stopBlock := storage.GetBlockByNumberWithBlockGetter(tx, startBlock.GetNumber()+uint64(stopOffSet)-1, p.config.Pala, makeBlockGetterFunc(p.BaseAPI))
	if stopBlock == nil {
		return nil, fmt.Errorf("stop block not found at %v", session)
	}

	resp.StopBlock = BlockStatus{
		BlockSn: stopBlock.GetBlockSn().String(),
		Height:  stopBlock.GetNumber(),
	}

	return resp, nil
}

type BidStatus struct {
	committee.MemberInfo
	ConsensusId tt.ConsensusId
}

func (p *PalaImpl) GetBidStatus(num *rpc.BlockNumber) ([]*BidStatus, error) {
	if num == nil || num.Int64() < rpc.LatestBlockNumber.Int64() {
		return nil, fmt.Errorf("invalid block number")
	}

	tx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	blockNum := uint64(num.Int64())
	if *num == rpc.LatestBlockNumber {
		bn := rawdb.ReadCurrentBlockNumber(tx)
		if bn == nil {
			return nil, fmt.Errorf("invalid block number")
		}
		blockNum = *bn
	}

	hash, err := rawdb.ReadCanonicalHash(tx, blockNum)
	if err != nil {
		log.Error("Read canonical hash failed", "number", blockNum, "err", err)
		return nil, fmt.Errorf("read canonical hash failed")
	}

	header := rawdb.ReadHeader(tx, hash, blockNum)
	reader := state.NewPlainState(tx, header.Number.Uint64(), make(map[common.Address][]common.CodeRecord))
	ibs := state.New(reader)

	stakes, err := precompile.GetCurrentBids(ibs)
	if err != nil {
		return nil, err
	}

	resp := []*BidStatus{}
	for _, stake := range stakes {
		memInfo := stake.ToMemberInfo()
		resp = append(resp, &BidStatus{
			*memInfo,
			tt.ConsensusIdFromPubKey(memInfo.PubVoteKey),
		})
	}

	return resp, nil
}

type TtTransferWithHash struct {
	From    common.Address  `json:"from"`
	To      *common.Address `json:"to,omitempty"`
	Value   *hexutil.Big    `json:"value,omitempty"`
	Error   *string         `json:"error,omitempty"`
	Reason  *string         `json:"reason,omitempty"`
	OpCode  string          `json:"opCode"`
	Indices []uint64        `json:"indices"`
	Gas     hexutil.Uint64  `json:"gas"`
	GasUsed hexutil.Uint64  `json:"gasUsed"`
	Hash    common.Hash     `json:"hash"`
}

func appendTransfer(ori []TtTransferWithHash, transfer *VmCall, h common.Hash) []TtTransferWithHash {
	var hv *hexutil.Big
	if transfer.OpCode != "DELEGATECALL" && transfer.OpCode != "STATICCALL" {
		var v big.Int
		v.Set(transfer.Value)
		hv = new(hexutil.Big)
		*hv = (hexutil.Big)(v)
	}
	withHash := TtTransferWithHash{
		From:    transfer.From,
		To:      transfer.To,
		Value:   hv,
		OpCode:  transfer.OpCode,
		Indices: transfer.Indices,
		Gas:     hexutil.Uint64(transfer.Gas),
		GasUsed: hexutil.Uint64(transfer.GasUsed),
		Hash:    h,
	}
	if transfer.Error != nil && len(*transfer.Error) != 0 {
		withHash.Error = transfer.Error
	}
	if transfer.Reason != nil && len(*transfer.Reason) != 0 {
		withHash.Reason = transfer.Reason
	}
	return append(ori, withHash)
}

func (p *PalaImpl) GetTtTransfersByBlockNumber(num *rpc.BlockNumber) ([]TtTransferWithHash, error) {
	if num == nil || num.Int64() < rpc.LatestBlockNumber.Int64() {
		return nil, fmt.Errorf("invalid block number")
	}

	dbTx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer dbTx.Rollback()

	blockNum := uint64(num.Int64())
	if *num == rpc.LatestBlockNumber {
		bn := rawdb.ReadCurrentBlockNumber(dbTx)
		if bn == nil {
			return nil, fmt.Errorf("invalid block number")
		}
		blockNum = *bn
	}

	if p.ttBlockLRU != nil {
		if it, ok := p.ttBlockLRU.Get(blockNum); ok {
			return it, nil
		}
	}

	// check pruning to ensure we have history at this block level
	err = p.BaseAPI.checkPruneHistory(dbTx, blockNum)
	if err != nil {
		return nil, err
	}

	block, err := p.blockByNumberWithSenders(dbTx, blockNum)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}

	ctx := context.Background()
	engine := p.engine()
	getHeader := func(hash common.Hash, n uint64) *types.Header {
		h, _ := p._blockReader.HeaderByNumber(ctx, dbTx, n)
		return h
	}

	reader := state.NewPlainState(dbTx, blockNum, make(map[common.Address][]common.CodeRecord))
	if err != nil {
		return nil, err
	}

	ibs := state.New(reader)
	header := block.HeaderNoCopy()

	sessionNum := blocksn.GetSessionFromDifficulty(header.Difficulty, header.Number, p.config.Pala)
	signer := types.MakeSigner(p.config, block.NumberU64(), sessionNum)
	rules := p.config.Rules(blockNum, 0, sessionNum)

	resp := []TtTransferWithHash{}

	for idx, tx := range block.Transactions() {
		msg, _ := tx.AsMessage(*signer, block.BaseFee(), rules)

		txContext := core.NewEVMTxContext(msg)
		txContext.TxHash = tx.Hash()
		stateRootCal := transactions.MakeStateRootFromDBGetter(dbTx)
		blockCtx := core.NewEVMBlockContext(header, core.GetHashFn(header, getHeader), engine, nil, stateRootCal)

		blockTracer := &ttBlockTracer{}

		vmenv := vm.NewEVM(blockCtx, txContext, ibs, p.config, vm.Config{
			Debug:  true,
			Tracer: blockTracer,
		})

		ibs.Prepare(tx.Hash(), block.Hash(), idx)
		res, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(tx.GetGas()), true /* refunds */, false /* gasBailout */)
		if err != nil {
			return nil, fmt.Errorf("transaction %x failed: %w", tx.Hash(), err)
		}

		transfers := blockTracer.getTransfers()
		transfers[0].Gas = tx.GetGas()
		transfers[0].GasUsed = res.UsedGas

		for _, transfer := range transfers {
			resp = appendTransfer(resp, transfer, tx.Hash())
		}

		_ = ibs.FinalizeTx(rules, reader)
	}

	p.ttBlockLRU.Add(blockNum, resp)

	return resp, nil
}

func (p *PalaImpl) TraceTransaction(hash common.Hash) ([]*TraceTransactionResult, error) {
	ctx := context.Background()
	tx, err := p.db.BeginRo(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	chainConfig, err := p.chainConfig(tx)
	if err != nil {
		return nil, err
	}
	// Retrieve the transaction and assemble its EVM context
	blockNum, ok, err := p.txnLookup(ctx, tx, hash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	// check pruning to ensure we have history at this block level
	err = p.BaseAPI.checkPruneHistory(tx, blockNum)
	if err != nil {
		return nil, err
	}

	block, err := p.blockByNumberWithSenders(tx, blockNum)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}
	var txnIndex uint64
	for i, transaction := range block.Transactions() {
		if transaction.Hash() == hash {
			txnIndex = uint64(i)
			break
		}
	}
	engine := p.engine()

	msg, blockCtx, txCtx, ibs, _, err := transactions.ComputeTxEnv(ctx, engine, block, chainConfig, p._blockReader, tx, int(txnIndex), p.historyV3(tx))
	if err != nil {
		return nil, err
	}

	tracer := NewScanTracer()

	vmenv := vm.NewEVM(blockCtx, txCtx, ibs, chainConfig, vm.Config{Debug: true, Tracer: tracer})
	ibs.Prepare(common.Hash{}, common.Hash{}, 0)

	_, err = core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.Gas()), true, false)
	if err != nil {
		return nil, fmt.Errorf("trace failed: %v", err)
	}

	return tracer.GetResults(), nil
}

type CommInfo struct {
	ProposerIds []tt.ConsensusId
	VoterIds    []tt.ConsensusId
}

type Notarization struct {
	VoterIds []tt.ConsensusId
	BlockSn  string
}

type BlockInfoResponse struct {
	BlockSn         string
	SessionCommInfo CommInfo
	Notarizations   []Notarization
}

func makeBlockGetterFunc(api *BaseAPI) storage.BlockGetFunc {
	return func(tx kv.Tx, hash common.Hash, num uint64) *types.Block {
		blk, err := api.blockWithSenders(tx, hash, num)
		if err != nil {
			return nil
		}
		return blk
	}
}

func (p *PalaImpl) GetBlockInfo(num *rpc.BlockNumber) (*BlockInfoResponse, error) {
	var b tt.Block
	if num == nil || num.Int64() < rpc.LatestBlockNumber.Int64() {
		return nil, fmt.Errorf("invalid block number")
	}

	tx, err := p.db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if *num == rpc.LatestBlockNumber {
		sn, err := storage.ReadFreshestNotarizedHeadSn(tx)
		if err != nil {
			return nil, err
		}
		b = storage.ReadBlockFromBlockSnWithBlockGetter(tx, sn, p.config.Pala, makeBlockGetterFunc(p.BaseAPI))
	} else {
		b = storage.GetBlockByNumberWithBlockGetter(tx, uint64(num.Int64()), p.config.Pala, makeBlockGetterFunc(p.BaseAPI))
	}
	if b == nil {
		return nil, fmt.Errorf("invalid chain sequence")
	}

	resp := &BlockInfoResponse{}
	mapSessionCommVoters := map[blocksn.Session][]tt.ConsensusId{}

	h := rawdb.ReadHeaderByNumber(tx, uint64(*num))
	if h == nil {
		return nil, fmt.Errorf("invalid chain sequence")
	}

	reader := state.NewPlainState(tx, h.Number.Uint64(), make(map[common.Address][]common.CodeRecord))
	ibs := state.New(reader)

	resp.BlockSn = b.GetBlockSn().String()
	currentSession := b.GetBlockSn().Epoch.Session
	currSessionCommInfo := storage.GetBlockCommittee(h, ibs, p.config.Pala)
	resp.SessionCommInfo = CommInfo{
		ProposerIds: getCommInfoProposerIds(currSessionCommInfo),
		VoterIds:    getCommInfoVoterIds(currSessionCommInfo),
	}
	mapSessionCommVoters[currentSession] = resp.SessionCommInfo.VoterIds

	unmarshaller := storage.NewDataUnmarshaller(p.config.Pala)
	decoder := storage.NewBlockImplDecoder(unmarshaller)
	notas := decoder.GetNotarizations(b, p.config.Pala)
	for _, nota := range notas {
		sess := nota.GetBlockSn().Epoch.Session

		var commVoteIds []tt.ConsensusId
		if _, ok := mapSessionCommVoters[sess]; !ok {
			blk := storage.ReadBlockFromBlockSnWithBlockGetter(tx, nota.GetBlockSn(), p.config.Pala, makeBlockGetterFunc(p.BaseAPI))
			header := rawdb.ReadHeader(tx, common.BytesToHash(blk.GetHash().Bytes()), blk.GetNumber())

			mapSessionCommVoters[sess] = getCommInfoVoterIds(storage.GetBlockCommittee(header, ibs, p.config.Pala))
		}
		commVoteIds = mapSessionCommVoters[sess]

		resp.Notarizations = append(resp.Notarizations, Notarization{
			BlockSn:  nota.GetBlockSn().String(),
			VoterIds: filterVotedVoterIds(nota.GetMissingVoterIdxs(), commVoteIds),
		})
	}

	return resp, nil
}

func filterVotedVoterIds(missingVoterIdxs []uint16, allVoters []tt.ConsensusId) []tt.ConsensusId {
	var voterIds []tt.ConsensusId
	missingVoterSet := make(map[uint16]bool)
	for _, v := range missingVoterIdxs {
		missingVoterSet[v] = true
	}
	for i := uint16(0); i < uint16(len(allVoters)); i++ {
		if _, ok := missingVoterSet[i]; !ok {
			voterIds = append(voterIds, allVoters[i])
		}
	}
	return voterIds
}

func getCommInfoProposerIds(comm *committee.CommInfo) []tt.ConsensusId {
	ids := []tt.ConsensusId{}
	for _, proposer := range comm.AccelInfo {
		ids = append(ids, tt.ConsensusIdFromPubKey(proposer.PubVoteKey))
	}
	return ids
}

func getCommInfoVoterIds(comm *committee.CommInfo) []tt.ConsensusId {
	ids := []tt.ConsensusId{}
	for _, voter := range comm.MemberInfo {
		ids = append(ids, tt.ConsensusIdFromPubKey(voter.PubVoteKey))
	}
	return ids
}
