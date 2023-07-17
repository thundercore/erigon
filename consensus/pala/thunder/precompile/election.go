package precompile

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/thunder/hardfork"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/bls"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/election"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
)

const (
	commElectionStakeMessagePrefix   = "stake"
	commElectionElectionResultPrefix = "electionResult"
	electionStakeTablePrefix         = "estp"
	electionFreezerTablePrefix       = "eftp"
	electionFreezerIndexPrefix       = "efip"

	// refundIdMaxLength = len(hash256()) + len(method.Id())
	// refundId should limited to a hash and abi packed method
	refundIDMaxLength = ttCommon.HashLength + 4
)

type commElection struct {
	base
}

func init() {

	// generate ABI from json
	{
		abi, err := abi.JSON(strings.NewReader(electionABIjson))
		if err != nil {
			debug.Fatal("could not parse CSTPC abi")
		}
		ElectionABI = abi
	}
}

// TODO add VotePubKeySig to this
type StakeMsgABI_0p5 struct {
	RewardAddress common.Address
	Stake         *big.Int
	GasPrice      *big.Int
	VotePubKey    []byte
	RefundID      []byte
}

// CSTPCABI is created by https://remix.ethereum.org with contract like that
//
//	contract CSTPCABI {
//		function bid(address rewardAddress, uint256 stake, uint256 gasPrice, bytes votePubKey, bytes refundID) {}
//		function getAvailableStake(bytes refundID) view returns(int) {}
//	}
var electionABIjson = `
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "rewardAddress",
				"type": "address"
			},
			{
				"name": "stake",
				"type": "uint256"
			},
			{
				"name": "gasPrice",
				"type": "uint256"
			},
			{
				"name": "votePubKey",
				"type": "bytes"
			},
			{
				"name": "refundID",
				"type": "bytes"
			}
		],
		"name": "bid",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "refundID",
				"type": "bytes"
			}
		],
		"outputs": [
			{
				"type": "int256"
			}
		],
		"name": "getAvailableStake",
		"stateMutability": "view",
		"type": "function"
	}
]
`

// CSTPCABI is exposed for stake in tool to pack its message
var ElectionABI abi.ABI

func (e *commElection) call(method *abi.Method, input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	switch method.Name {
	case "bid":
		var arg StakeMsgABI_0p5

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}

		pubkey, err := bls.PublicKeyFromBytes(arg.VotePubKey)
		if err != nil {
			e.logger.Warn("Error from PublicKeyFromBytes sender",
				"RewardAddress", arg.RewardAddress.Hex(),
				"error", err,
				"VoteKey", hex.EncodeToString(arg.VotePubKey))
			return nil, err
		}

		var msg = &election.StakeInfo{
			StakeMsg: election.StakeMsg{
				Stake:      arg.Stake,
				Coinbase:   arg.RewardAddress,
				GasPrice:   arg.GasPrice,
				PubVoteKey: pubkey,
			},
			StakingAddr: contract.Caller(),
			RefundID:    arg.RefundID,
		}

		return nil, e.abiBid(evm, contract, msg)

	case "getAvailableStake":
		var RefundID []byte

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&RefundID, vs); err != nil {
			return nil, err
		}

		return e.abiGetAvailableStake(evm, contract, RefundID)
	default:
		return nil, fmt.Errorf("no such method")
	}
}

func (c *commElection) RequiredGas(input []byte) uint64 {
	// We allow the Run() part of this precompiled contract to consume more gas
	// Note the elect method is hacked to always be 0 gas (despite using gas to call refund())
	// this is so that elect will never go over the block gas limit
	// We set 0 here and comsuming gas in Run() since we have vm.Contract to use
	return 0
}

// Run processes the PST/EST and stores the result in the stateb
// it does not conform to Ethereum ABI because it should never be called from a smart contract
func (e *commElection) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	if len(input) == 0 {
		return e.elect(evm, contract)
	}

	if len(input) < 4 {
		return nil, vm.ErrExecutionReverted
	}

	id := input[:4]
	arg := input[4:]

	method, err := ElectionABI.MethodById(id)
	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	ret, err := e.call(method, arg, evm, contract)

	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	return ret, nil
}

func (e *commElection) elect(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
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
	result := election.Elect(evm.ChainConfig().Pala.Hardforks, currentBids,
		freezeStakeBound(stakeTable, freezerTable, freezerIndex),
		int64(session))

	if result == nil {
		e.logger.Warn("Election failed")
		return nil, vm.ErrExecutionReverted
	}

	SetCurrentElectionResult(state, result)

	refundAll(evm, contract, stakeTable)

	// refund() should not have enough gas to call bid() meaning it's impossible for the stake message
	// map to change before/after refundAll() above. Still, we clear after refundAll() to follow
	// smart contract coding conventions.
	StakeMessages(state).Clear()

	return nil, nil
}

// isValidBid check incoming bid make sense, bls key should be 128 bytes.
// Refund ID should be less than votingkey and gas price should never be zero.
func isValidBid(hk *hardfork.Hardforks, stakeMsg *election.StakeInfo, sessionNumber int64) bool {
	isValid := stakeMsg.GasPrice.Cmp(election.MinBidPrice.GetValueHardforkAtSession(hk, sessionNumber)) >= 0 &&
		len(stakeMsg.RefundID) <= refundIDMaxLength
	if !isValid {
		logger.Warn("invalid bid",
			"StakingAddr",
			stakeMsg.StakingAddr.Hex(),
			"GasPrice", stakeMsg.GasPrice,
			"RefundID len", len(stakeMsg.RefundID))
	}
	return isValid
}

func StakeMessages(stateDB evmtypes.IntraBlockState) *ByteMap {
	return NewByteMap(ttCommon.CommElectionTPCAddress, stateDB, commElectionStakeMessagePrefix)
}

func ElectionResults(stateDB evmtypes.IntraBlockState) *ByteList {
	return NewByteList(stateDB, ttCommon.CommElectionTPCAddress, commElectionElectionResultPrefix)
}

func (c *commElection) abiBid(evm *vm.EVM, contract *vm.Contract, stakeMsg *election.StakeInfo) error {

	c.logger.Info("bid",
		"Coinbase", stakeMsg.Coinbase.Hex(),
		"Stake", ttCommon.WeiToEther(stakeMsg.Stake).String(),
		"GasPrice", stakeMsg.GasPrice.String(),
		"VoteKey", hex.EncodeToString(stakeMsg.PubVoteKey.ToBytes())[:16],
		"from", contract.Caller().Hex(),
		"value", contract.Value().String(),
		"refundID", hex.EncodeToString(stakeMsg.RefundID),
	)

	session := blocksn.GetSessionFromDifficulty(evm.Context().Difficulty, big.NewInt(int64(evm.Context().BlockNumber)), evm.ChainConfig().Pala)
	if !isValidBid(evm.ChainConfig().Pala.Hardforks, stakeMsg, int64(session)) {
		return fmt.Errorf("invalid bid")
	}

	bm := StakeMessages(evm.IntraBlockState())

	key := makeRefundKey(stakeMsg.StakingAddr, stakeMsg.RefundID)

	uniqueKey := string(stakeMsg.PubVoteKey.ToBytes()) + key

	gas := gasByteMapInsert(len(key), len(stakeMsg.ToBytes()))

	if !contract.UseGas(gas) {
		c.logger.Warn("incoming bid is not enough gas", "expected", gas,
			"sender", contract.Caller().Hex())
		return vm.ErrOutOfGas
	}

	bm.InsertOrReplaceEntry(uniqueKey, stakeMsg)

	// if no money was sent with this transaction, no need to update the stake table
	if contract.Value().Sign() == 0 {
		c.logger.Debug("incoming bid sends no money", "sender", contract.Caller().Hex())
		return nil
	}

	stakeTable := NewByteMap(ttCommon.CommElectionTPCAddress, evm.IntraBlockState(), electionStakeTablePrefix)

	gas = gasByteMapReplace(len(key), ttCommon.HashLength)
	if !contract.UseGas(gas) {
		c.logger.Info("incoming bid: out of gas", "sender", contract.Caller().Hex())
		return vm.ErrOutOfGas
	}

	var current stakeValue
	err := stakeTable.FindEntry(key, &current)

	if err != nil {
		current.Value = big.NewInt(0).Set(contract.Value().ToBig())
	} else {
		current.Value.Add(current.Value, contract.Value().ToBig())
	}

	stakeTable.InsertOrReplaceEntry(key, &current)

	return nil
}

func (c *commElection) abiGetAvailableStake(evm *vm.EVM, contract *vm.Contract, refundID []byte) ([]byte, error) {
	output := GetAvailableElectionStake(evm.IntraBlockState(), contract.Caller(), refundID)

	return common.BigToHash(output).Bytes(), nil
}
