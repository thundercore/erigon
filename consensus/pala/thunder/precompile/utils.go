package precompile

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"

	"github.com/holiman/uint256"
	libCommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/erigon/common"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/election"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
)

type stakeValue struct {
	Value *big.Int
}

func (sv *stakeValue) FromBytes(input []byte) error {
	if len(input) > ttCommon.HashLength {
		input = input[len(input)-ttCommon.HashLength:]
	} else {
		input = common.LeftPadBytes(input, ttCommon.HashLength)
	}

	sv.Value = libCommon.BytesToHash(input).Big()

	return nil
}

func (sv *stakeValue) ToBytes() []byte {
	return libCommon.BigToHash(sv.Value).Bytes()
}

type frozenIndex string

func (fi *frozenIndex) ToBytes() []byte {
	return []byte(*fi)
}

func (fi *frozenIndex) FromBytes(input []byte) error {
	*fi = frozenIndex(input)
	return nil
}

// unfreezeStake adds stake from freezerTable to stakeTable
func unfreezeStake(stakeTable, freezerTable, freezerIndex *ByteMap) {
	keys := freezerTable.Keys()

	for _, key := range keys {
		var frozen, current stakeValue
		err := freezerTable.FindEntry(key, &frozen)
		if err != nil {
			debug.Bug("freezerTable broken.")
		}

		err = stakeTable.FindEntry(key, &current)
		if err != nil {
			current.Value = big.NewInt(0)
		}
		current.Value.Add(current.Value, frozen.Value)
		stakeTable.InsertOrReplaceEntry(key, &current)
	}
	// current implementation guarantees that freezer table will have all value transferred out of it at this point (assuming no refund txs fail, but that's the user's problem)  so it's safe to clear the list here.
	freezerTable.Clear()
	freezerIndex.Clear()
}

func GetCurrentBids(state evmtypes.IntraBlockState) ([]*election.StakeInfo, error) {
	bm := StakeMessages(state)

	keys := bm.Keys()

	stakeInfos := make([]*election.StakeInfo, len(keys))

	for i, k := range keys {
		stakeInfos[i] = &election.StakeInfo{}

		err := bm.FindEntry(k, stakeInfos[i])

		if err != nil {
			debug.Bug("StakeMessageTable broken.")
		}
	}

	return stakeInfos, nil
}

func GetAvailableElectionStake(state evmtypes.IntraBlockState, addr libCommon.Address, refundID []byte) *big.Int {
	freezerTable := NewByteMap(ttCommon.CommElectionTPCAddress, state, electionFreezerTablePrefix)
	stakeTable := NewByteMap(ttCommon.CommElectionTPCAddress, state, electionStakeTablePrefix)

	var staked, frozen stakeValue
	key := makeRefundKey(addr, refundID)
	err1 := freezerTable.FindEntry(key, &frozen)
	err2 := stakeTable.FindEntry(key, &staked)

	output := big.NewInt(0)
	if err1 == nil {
		output.Add(output, frozen.Value)
	}
	if err2 == nil {
		output.Add(output, staked.Value)
	}

	return output
}

// makeRefundKey: (stakingAddr, refundInfo) -> key
func makeRefundKey(addr libCommon.Address, input []byte) string {
	s := append(addr.Bytes(), input...)
	return string(s)
}

// getRefundAddress: (key) -> refundAddress
func getRefundAddress(key string) libCommon.Address {
	bytes := []byte(key)
	return libCommon.BytesToAddress(bytes[:20])
}

// getRefundInput: (key) -> refundID
func getRefundInput(key string) []byte {
	bytes := []byte(key)
	return bytes[20:]
}

// freezeStake will move required stake from the stakeTable to freezerTable
// if there is insufficient stake, freezeStake will return false
// freezeStake will map refundKey to voting key in the freezerIndex ByteMap as well which may eventually be used for punishment in some future version (currently unused)
func freezeStake(stakeTable, freezerTable, freezerIndex *ByteMap, s *election.StakeInfo) bool {
	key := makeRefundKey(s.StakingAddr, s.RefundID)

	var current, frozen stakeValue
	err := stakeTable.FindEntry(key, &current)
	if err != nil {
		return false
	}

	if s.Stake.Cmp(current.Value) > 0 {
		return false
	}

	err = freezerTable.FindEntry(key, &frozen)
	if err != nil {
		frozen.Value = big.NewInt(0)
	}
	current.Value.Sub(current.Value, s.Stake)
	frozen.Value.Add(frozen.Value, s.Stake)

	stakeTable.InsertOrReplaceEntry(key, &current)
	freezerTable.InsertOrReplaceEntry(key, &frozen)

	freezeKey := string(s.PubVoteKey.ToBytes())
	index := frozenIndex(key)
	freezerIndex.InsertOrReplaceEntry(freezeKey, &index)

	return true
}

func freezeStakeBound(stakeTable, freezerTable, freezerIndex *ByteMap) func(s *election.StakeInfo) bool {
	return func(s *election.StakeInfo) bool {
		return freezeStake(stakeTable, freezerTable, freezerIndex, s)
	}
}

// clear stake table
func refundAll(evm *vm.EVM, contract *vm.Contract, stakeTable *ByteMap) {
	keys := stakeTable.Keys()

	for _, key := range keys {
		var current stakeValue
		err := stakeTable.FindEntry(key, &current)
		if err != nil {
			debug.Bug("stakeTable broken.")
		}

		// we chose len(key) because len(key) < len(StakeMsg) and len(key) < len(unique)
		// and gas of bid() should be gasByteMapInsert(len(uniqueKey), len(StakeMsg))
		// it MUST be the case that refund gas < bid gas otherwise it is possible to get free gas
		// from refund() after bidding
		gasLimit := gasByteMapInsert(len(key), len(key))

		// EVM INVARIANT BREAKING
		// fake the gas in the contract
		contract.Gas = gasLimit
		_, err = evmCompatibleCall(evm, contract, getRefundAddress(key), getRefundInput(key), current.Value, gasLimit)

		// if refund value is 0, maybe we can skip the CALL?
		if current.Value.Sign() != 0 {
			logger.Info("RefundAll", "to", getRefundAddress(key).Hex(), "value", current.Value, "err", err)
		}
	}

	// EVM INVARIANT BREAKING
	// PST costs 0 gas, so contract.Gas should be 0 coming into this function
	// lets make sure it's 0 going out of this function too :)
	contract.Gas = 0

	stakeTable.Clear()
}

func safeRefundAll(evm *vm.EVM, contract *vm.Contract, stakeTable *ByteMap) {
	keys := stakeTable.Keys()

	for _, key := range keys {
		var current stakeValue
		err := stakeTable.FindEntry(key, &current)
		if err != nil {
			debug.Bug("stakeTable broken.")
		}

		// we chose len(key) because len(key) < len(StakeMsg) and len(key) < len(unique)
		// and gas of bid() should be gasByteMapInsert(len(uniqueKey), len(StakeMsg))
		// it MUST be the case that refund gas < bid gas otherwise it is possible to get free gas
		// from refund() after bidding
		gasLimit := gasByteMapInsert(len(key), len(key))

		// EVM INVARIANT BREAKING
		// fake the gas in the contract
		contract.Gas = gasLimit

		refundAddress := getRefundAddress(key)
		refundInput := getRefundInput(key)

		isContract := len(evm.IntraBlockState().GetCode(refundAddress)) != 0

		// only refund to plan address or vault contract address
		if refundAddress == ttCommon.CommElectionTPCAddress || !isContract {
			_, err = evmCompatibleCall(evm, contract, refundAddress, refundInput, current.Value, gasLimit)
		} else {
			uint256Value := new(uint256.Int)
			uint256Value.SetBytes(current.Value.Bytes())
			if current.Value.Sign() != 0 && !evm.Context().CanTransfer(evm.IntraBlockState(), contract.Address(), uint256Value) {
				err = vm.ErrInsufficientBalance
			} else {
				evm.Context().Transfer(evm.IntraBlockState(), contract.Address(), refundAddress, uint256Value, false)
			}
		}

		// if refund value is 0, maybe we can skip the CALL?
		if current.Value.Sign() != 0 {
			logger.Info("RefundAll", "to", getRefundAddress(key).Hex(), "value", current.Value, "err", err)
		}
	}

	// EVM INVARIANT BREAKING
	// PST costs 0 gas, so contract.Gas should be 0 coming into this function
	// lets make sure it's 0 going out of this function too :)
	contract.Gas = 0

	stakeTable.Clear()
}

// GetCurrentElectionResult returns the current election result if one exists otherwise nil.
func GetCurrentElectionResult(state evmtypes.IntraBlockState) *election.Result {
	// TODO maybe better to use Ethereum ABI interface to get this data instead of
	// reading it directly out of the StateDB
	raw := ElectionResults(state).ToSlice()
	if len(raw) == 0 {
		return nil
	}

	result := election.Result{}
	err := result.FromBytes(raw[0])
	if err != nil {
		debug.Fatal("GetCurrentElectionResult error: %v", err)
	}
	return &result
}

func SetCurrentElectionResult(state evmtypes.IntraBlockState, result *election.Result) {
	// THUNDER-490: Sort committees based PubVoteKey, so the output will be same if bidder arguments
	// are the same whatever the orders of bidder TXs
	sort.Slice(result.Members, func(i, j int) bool {
		return bytes.Compare(result.Members[i].PubVoteKey.ToBytes(),
			result.Members[j].PubVoteKey.ToBytes()) == -1
	})
	bl := ElectionResults(state)
	bl.Clear()
	bl.Append(result.ToBytes())
}

func evmCompatibleCall(evm *vm.EVM, contract *vm.Contract, addr libCommon.Address, input []byte, value *big.Int, gas uint64) (ret []byte, err error) {
	// NOTE: EVM.Call() assuming code only reverted or out of gas issue.
	// If EVM.run() returns other error than ErrExecutionReverted, the Gas would be taken,
	// We should change the returning error code of our precompiled contract, if there is any.
	var returnGas uint64

	if !contract.UseGas(gas) {
		return nil, vm.ErrOutOfGas
	}

	uint256Value := new(uint256.Int)
	overflow := uint256Value.SetFromBig(value)

	if overflow {
		return nil, fmt.Errorf("value overflow")
	}

	ret, returnGas, err = evm.Call(contract, addr, input, gas, uint256Value, false)

	contract.Gas += returnGas

	return ret, err
}

func evmABICall(evm *vm.EVM, contract *vm.Contract, addr libCommon.Address, value *big.Int, gas uint64, method *abi.Method, args ...interface{}) (ret []byte, err error) {
	packedArgs, err := method.Inputs.Pack(args...)

	if err != nil {
		return nil, err
	}

	input := append(method.ID, packedArgs...)

	return evmCompatibleCall(evm, contract, addr, input, value, gas)
}

func IsTxPST(tx types.Transaction) bool {
	if tx == nil {
		return false
	}
	if tx.GetTo() == nil {
		return false
	}
	// PST goes to ETPC address
	if *tx.GetTo() != ttCommon.CommElectionTPCAddress {
		return false
	}
	// PST has empty payload
	if len(tx.GetData()) != 0 {
		return false
	}
	return true
}
