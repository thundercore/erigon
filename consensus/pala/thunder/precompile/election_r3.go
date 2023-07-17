package precompile

import (
	"math/big"

	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/election"
	"github.com/ledgerwatch/erigon/core/vm"
)

// electionR2ABIjson is created by https://remix.ethereum.org with contract like that
// contract CSTPCABI {
//    function bid(address rewardAddress, uint256 stake, uint256 gasPrice, bytes votePubKey, uint session, uint nonce, bytes sig, bytes refundID) {}
//    function getAvailableStake(bytes refundID) view returns(int) {}
//    function getNonce(bytes32 key) view returns(uint) {}
// }
//

type commElectionR3 struct {
	commElectionR2
}

func (e *commElectionR3) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	if len(input) == 0 {
		return e.elect(evm, contract)
	}

	if len(input) < 4 {
		return nil, vm.ErrExecutionReverted
	}

	id := input[:4]
	arg := input[4:]

	method, err := ElectionR2ABI.MethodById(id)
	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	ret, err := e.commElectionR2.call(method, arg, evm, contract)

	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	return ret, nil
}

func (e *commElectionR3) elect(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	if !evm.TxContext().GasPrice.IsZero() {
		return nil, vm.ErrExecutionReverted
	}

	if evm.TxContext().Origin != contract.Caller() {
		return nil, vm.ErrExecutionReverted
	}

	state := evm.IntraBlockState()
	stakeTable := NewByteMap(ttCommon.CommElectionTPCAddress, state, electionStakeTablePrefix)
	freezerTable := NewByteMap(ttCommon.CommElectionTPCAddress, state, electionFreezerTablePrefix)
	freezerIndex := NewByteMap(ttCommon.CommElectionTPCAddress, state, electionFreezerIndexPrefix)

	unfreezeStake(stakeTable, freezerTable, freezerIndex)

	currentBids, err := GetCurrentBids(state)
	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	session := blocksn.GetSessionFromDifficulty(evm.Context().Difficulty, big.NewInt(int64(evm.Context().BlockNumber)), evm.ChainConfig().Pala)
	// run the election and move funds from stake table to freezer table
	result := election.ElectR3(evm.ChainConfig().Pala.Hardforks, currentBids,
		freezeStakeBound(stakeTable, freezerTable, freezerIndex),
		int64(session))

	if result == nil {
		e.logger.Warn("Election failed")
		return nil, vm.ErrExecutionReverted
	}

	SetCurrentElectionResult(state, result)
	safeRefundAll(evm, contract, stakeTable)

	// refund() should not have enough gas to call bid() meaning it's impossible for the stake message
	// map to change before/after refundAll() above. Still, we clear after refundAll() to follow
	// smart contract coding conventions.
	StakeMessages(state).Clear()
	Nonces(state).Clear()

	return nil, nil
}
