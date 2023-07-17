package pala

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"
	types2 "github.com/ledgerwatch/erigon-lib/types"

	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/reward"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/storage"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/params"
	"github.com/ledgerwatch/erigon/rpc"

	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
)

const (
	// Future block time is large for now, and can be reconfigured at a later date
	allowedFutureBlockTime = 365 * 24 * 3600 * time.Second
)

var (
	errSealOperationOnGenesisBlock = errors.New(
		"verifySeal/Seal operations on genesis block not permitted")
	defaultCoinbaseAddress = ttCommon.DefaultCoinbaseAddress

	// Errors for unused fields not set to zero/empty
	errNonEmptyUncleHash = errors.New("non empty uncle hash")
	errNonDefaultAddress = errors.New("non default coinbase address")
	errNonZeroDifficulty = errors.New("non zero difficulty")
	errNonEmptyExtra     = errors.New("non empty extra")

	errUnknownBlock = errors.New("block number is nil")

	// Used by ethhash for DAO header
	zeroExtraData = make([]byte, 0)

	zeroUncleHash = types.EmptyUncleHash

	unityDifficulty = big.NewInt(1)
)

type Pala struct {
	Config *chain.Config
	Db     kv.RwDB
}

func New(cfg *chain.Config, db kv.RwDB) *Pala {
	return &Pala{Config: cfg, Db: db}
}

// Author implements consensus.Engine.
func (p *Pala) Author(header *types.Header) (common.Address, error) {
	return defaultCoinbaseAddress, nil
}

// CalcDifficulty implements consensus.Engine
// CalcDifficulty is used for difficulty adjustment in PoW algorithms, and
// is not needed for PoS consensus schemes.
func (p *Pala) CalcDifficulty(chain consensus.ChainHeaderReader, _, _ uint64, _ *big.Int, parentNumber uint64, parentHash, _ common.Hash, _ uint64) *big.Int {
	return big.NewInt(0)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (p *Pala) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header,
	seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error)

	go func() {
		for i, header := range headers {
			var parent *types.Header
			if i == 0 {
				parent = chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
			} else {
				parent = headers[i-1]
			}
			var err error
			if parent == nil {
				err = consensus.ErrUnknownAncestor
			} else {
				err = p.verifyHeader(chain, parent, header, seals[i])
			}

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func verifyHeaderUnusedFieldsAreDefault(header *types.Header, config *chain.PalaConfig) error {
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != zeroUncleHash {
		return errNonEmptyUncleHash
	}
	if header.Coinbase != defaultCoinbaseAddress {
		return errNonDefaultAddress
	}

	if !config.IsPala(header.Number.Uint64()) && header.Difficulty.Cmp(unityDifficulty) != 0 {
		return errNonZeroDifficulty
	}

	session := blocksn.GetSessionFromDifficulty(header.Difficulty, header.Number, config)
	if !config.IsConsensusInfoInHeader.GetValueHardforkAtSession(config.Hardforks, int64(session)) && !bytes.Equal(header.Extra, zeroExtraData) {
		return errNonEmptyExtra
	}
	return nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (p *Pala) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header,
	seal bool) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	// If the block already exists, skip verification
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	return p.verifyHeader(chain, parent, header, seal)
}

func (p *Pala) verifyHeader(chain consensus.ChainHeaderReader, parent *types.Header,
	header *types.Header, seal bool) error {
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Don't check future blocks.
	if header.Time > uint64(time.Now().Add(allowedFutureBlockTime).Unix()) {
		return consensus.ErrFutureBlock
	}
	// check that the new block's timestamp is strictly greater than it's parents
	if header.Time <= parent.Time {
		return fmt.Errorf("block timestamp (%d) <= parent's timestamp (%d)",
			header.Time, parent.Time)
	}

	if err := verifyHeaderUnusedFieldsAreDefault(header, chain.Config().Pala); err != nil {
		return err
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed,
			header.GasLimit)
	}
	// Verify the engine specific seal securing the block
	if seal {
		if err := p.VerifySeal(chain, header); err != nil {
			return err
		}
	}

	return nil
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (p *Pala) VerifyUncles(chain consensus.ChainReader, header *types.Header, uncles []*types.Header) error {
	if len(uncles) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine.
// In thunder protocol, we don't store signed proposals in the block.
func (p *Pala) VerifySeal(chain consensus.ChainHeaderReader, header *types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errSealOperationOnGenesisBlock
	}
	return nil
}

// All header fields which are not relevant in Thunder protocol are set to predefined zero values.
func setHeaderUnusedFieldsToDefault(header *types.Header, config *chain.PalaConfig) {
	header.UncleHash = zeroUncleHash
	header.Coinbase = defaultCoinbaseAddress
	if !config.IsPala(header.Number.Uint64()) {
		header.Difficulty = unityDifficulty
	}

	session := blocksn.GetSessionFromDifficulty(header.Difficulty, header.Number, config)
	if !config.IsConsensusInfoInHeader.GetValueHardforkAtSession(config.Hardforks, int64(session)) {
		header.Extra = zeroExtraData
	}
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (p *Pala) Prepare(chain consensus.ChainHeaderReader, header *types.Header, state *state.IntraBlockState) error {
	setHeaderUnusedFieldsToDefault(header, chain.Config().Pala)
	number := header.Number.Uint64()

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (p *Pala) Finalize(cconfig *chain.Config, header *types.Header, state *state.IntraBlockState,
	txs types.Transactions, uncles []*types.Header, r types.Receipts, withdrawals []*types.Withdrawal,
	e consensus.EpochReader, chain consensus.ChainHeaderReader, syscall consensus.SystemCall,
) (types.Transactions, types.Receipts, error) {
	panic("should use FinalizeAndAssemble instead of Finalize")
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (p *Pala) FinalizeAndAssemble(chainConfig *chain.Config, header *types.Header, state *state.IntraBlockState,
	txs types.Transactions, uncles []*types.Header, receipts types.Receipts, withdrawals []*types.Withdrawal,
	e consensus.EpochReader, chain consensus.ChainHeaderReader, syscall consensus.SystemCall, call consensus.Call,
) (*types.Block, types.Transactions, types.Receipts, error) {
	p.processPala(header, state, chain, txs, receipts)

	// header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	setHeaderUnusedFieldsToDefault(header, p.Config.Pala)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, nil), txs, receipts, nil
}

func (p *Pala) processPala(header *types.Header, state *state.IntraBlockState, chain consensus.ChainHeaderReader,
	txs types.Transactions, receipts []*types.Receipt) {
	currentInfo := storage.GetBlockCommittee(header, state, p.Config.Pala)
	session := blocksn.GetSessionFromDifficulty(header.Difficulty, header.Number, p.Config.Pala)

	rewardScheme := p.Config.Pala.RewardScheme.GetValueHardforkAtSession(p.Config.Pala.Hardforks, int64(session))

	switch rewardScheme {
	case "thunderella":
		reward.UpdateFees(state, txs, receipts, currentInfo.ClearingGasPrice(), currentInfo.AccelGasPrice())
	case "pala-r2.1":
		reward.UpdateFeesR2P5(state, txs, receipts)
	case "inflation":
		inflation := p.Config.Pala.TokenInflation.GetValueHardforkAtSession(p.Config.Pala.Hardforks, int64(session))
		if storage.IsAfterStopBlockHeader(header, false, p.Config.Pala) {
			inflation = common.Big0
		}
		commRewardRatio := p.Config.Pala.CommitteeRewardRatio.GetValueHardforkAtSession(p.Config.Pala.Hardforks, int64(session))
		reward.UpdateFeesR4(state, txs, receipts, inflation, header.BaseFee, commRewardRatio)
	default:
		debug.Bug("Unsupported reward scheme.")
	}

	if !storage.IsStopBlockHeader(header, p.Config.Pala) {
		return
	}

	fakeGasPool := new(core.GasPool).AddGas(math.MaxUint64)
	origBase := header.BaseFee
	header.BaseFee = common.Big0
	defer func() {
		header.BaseFee = origBase
	}()

	msg := types.NewMessage(ttCommon.PSTAddr, &ttCommon.CommElectionTPCAddress,
		state.GetNonce(ttCommon.PSTAddr), uint256.NewInt(0), params.TxGas, uint256.NewInt(0),
		uint256.NewInt(0), uint256.NewInt(0), []byte{}, types2.AccessList{}, true, false)

	getHashFn := core.GetHashFn(header, chain.GetHeader)

	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(header, getHashFn, p, &ttCommon.CommElectionTPCAddress, nil)

	evm := vm.NewEVM(evmContext, txContext, state, p.Config, vm.Config{})
	if _, err := core.ApplyMessage(evm, msg, fakeGasPool, true, false); err != nil {
		debug.Bug("could not apply PST, %v", err)
	}

	switch rewardScheme {
	case "pala-r2.1", "thunderella":
		reward.Distribute(currentInfo, state)
	case "inflation":
		reward.DistributeR4(currentInfo, state)
	}
}

// Seal implements consensus.Engine.
// 'stop' channel is not important in case of thunder protocol. Its only use is to abort mining
// before the nonce is found (see ethhash/consensus.go)
// Note that we seal the blocks irrespective of transaction count i.e. can be 0, that's because
// thunder protocol may need to seal empty block if an alive message is due,
// but there are no transactions.
// TODO: document contract with callee
func (p *Pala) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block,
	stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errSealOperationOnGenesisBlock
	}

	results <- block.WithSeal(header)
	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (p *Pala) SealHash(header *types.Header) common.Hash {
	return common.Hash{}
}

// Close implements consensus.Engine close. Thunder does not have background threads
func (p *Pala) Close() error {
	return nil
}

func (p *Pala) APIs(consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{}
}

func (p *Pala) GenerateSeal(chain consensus.ChainHeaderReader, currnt, parent *types.Header, call consensus.Call) []byte {
	return nil
}

func (p *Pala) Initialize(config *chain.Config, chain consensus.ChainHeaderReader, e consensus.EpochReader, header *types.Header,
	state *state.IntraBlockState, txs []types.Transaction, uncles []*types.Header, syscall consensus.SystemCall) {
}

func (p *Pala) IsServiceTransaction(sender common.Address, syscall consensus.SystemCall) bool {
	return false
}

func (p *Pala) Type() chain.ConsensusName {
	return chain.PalaConsensus
}
