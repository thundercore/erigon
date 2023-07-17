package precompile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/bls"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/election"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/core/vm/evmtypes"

	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
)

const (
	nonceTablePrefix = "nonce"
)

func init() {
	// generate ABI from json
	{
		_abi, err := abi.JSON(strings.NewReader(electionR2ABIjson))
		if err != nil {
			debug.Fatal("could not parse CSTPC abi")
		}
		ElectionR2ABI = _abi
	}
}

func Nonces(stateDB evmtypes.IntraBlockState) *ByteMap {
	return NewByteMap(ttCommon.CommElectionTPCAddress, stateDB, nonceTablePrefix)
}

type StakeMsgR2ABI struct {
	RewardAddress common.Address
	Stake         *big.Int
	GasPrice      *big.Int
	VotePubKey    []byte
	Session       *big.Int
	Nonce         *big.Int
	Sig           []byte
	RefundID      []byte // not used in vault
}

// electionR2ABIjson is created by https://remix.ethereum.org with contract like that
//
//	contract CSTPCABI {
//	   function bid(address rewardAddress, uint256 stake, uint256 gasPrice, bytes votePubKey, uint session, uint nonce, bytes sig, bytes refundID) {}
//	   function getAvailableStake(bytes refundID) view returns(int) {}
//	   function getNonce(bytes32 key) view returns(uint) {}
//	}
var electionR2ABIjson = `
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
				"name": "session",
				"type": "uint256"
			},
			{
				"name": "nonce",
				"type": "uint256"
			},
			{
				"name": "sig",
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
				"name": "key",
				"type": "bytes32"
			}
		],
		"name": "getNonce",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
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
		"name": "getAvailableStake",
		"outputs": [
			{
				"name": "",
				"type": "int256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]
`

// CSTPCABI is exposed for stake in tool to pack its message
var ElectionR2ABI abi.ABI

type commElectionR2 struct {
	base
}

func (e *commElectionR2) call(method *abi.Method, input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	switch method.Name {
	case "bid":
		var arg StakeMsgR2ABI

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
				"voteKey", hex.EncodeToString(arg.VotePubKey))
			return nil, err
		}

		sig, err := bls.SignatureFromBytes(arg.Sig)
		if err != nil {
			e.logger.Warn("Failed to get signature for sender", "RewardAddress", arg.RewardAddress.Hex(), "error", err)
			return nil, err
		}

		var msg = &election.SignedStakeInfo{
			StakeInfo: election.StakeInfo{
				StakeMsg: election.StakeMsg{
					Stake:      arg.Stake,
					Coinbase:   arg.RewardAddress,
					GasPrice:   arg.GasPrice,
					PubVoteKey: pubkey,
				},
				StakingAddr: contract.Caller(),
				RefundID:    arg.RefundID,
			},
			Session: arg.Session,
			Nonce:   arg.Nonce,
			Sig:     sig,
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
	case "getNonce":
		var key common.Hash
		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&key, vs); err != nil {
			return nil, err
		}
		return e.abiGetNonce(evm, key)
	default:
		return nil, fmt.Errorf("no such method")
	}
}

func (c *commElectionR2) RequiredGas(input []byte) uint64 {
	// We allow the Run() part of this precompiled contract to consume more gas
	// Note the elect method is hacked to always be 0 gas (despite using gas to call refund())
	// this is so that elect will never go over the block gas limit
	// We set 0 here and comsuming gas in Run() since we have vm.Contract to use
	return 0
}

// Run processes the PST/EST and stores the result in the stateb
// it does not conform to Ethereum ABI because it should never be called from a smart contract
func (e *commElectionR2) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
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

	ret, err := e.call(method, arg, evm, contract)

	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	return ret, nil
}

func (e *commElectionR2) elect(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
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
	Nonces(state).Clear()

	return nil, nil
}

func (c *commElectionR2) abiBid(evm *vm.EVM, contract *vm.Contract, signedStakeInfo *election.SignedStakeInfo) error {
	c.logger.Info("bid",
		"Coinbase",
		signedStakeInfo.Coinbase.Hex(),
		"Stake",
		ttCommon.WeiToEther(signedStakeInfo.Stake).String(),
		"Gas",
		signedStakeInfo.GasPrice.String(),
		"VoteKey",
		hex.EncodeToString(signedStakeInfo.PubVoteKey.ToBytes())[:16])
	c.logger.Info("    ",
		"from",
		contract.Caller().Hex(),
		"value",
		contract.Value().String(),
		"refundID",
		hex.EncodeToString(signedStakeInfo.RefundID))

	session := blocksn.GetSessionFromDifficulty(evm.Context().Difficulty, big.NewInt(int64(evm.Context().BlockNumber)), evm.ChainConfig().Pala)
	if !isValidBid(evm.ChainConfig().Pala.Hardforks, &signedStakeInfo.StakeInfo, int64(session)) {
		return fmt.Errorf("invalid bid")
	}
	if err := c.verifySigAndIncNonce(signedStakeInfo, contract, evm); err != nil {
		return err
	}

	key := makeRefundKey(signedStakeInfo.StakingAddr, signedStakeInfo.RefundID)
	uniqueKey := string(signedStakeInfo.PubVoteKey.ToBytes()) + key

	gas := gasByteMapInsert(len(uniqueKey), len(signedStakeInfo.StakeInfo.ToBytes()))

	if !contract.UseGas(gas) {
		c.logger.Warn("incoming bid is not enough gas", "expected", gas, "sender",
			contract.Caller().Hex())
		return vm.ErrOutOfGas
	}

	bm := StakeMessages(evm.IntraBlockState())
	bm.InsertOrReplaceEntry(uniqueKey, &signedStakeInfo.StakeInfo)

	// if no money was sent with this transaction, no need to update the stake table
	if contract.Value().Sign() == 0 {
		c.logger.Debug("incoming bid sends no money, sender", "sender", contract.Caller().Hex())
		return nil
	}

	stakeTable := NewByteMap(ttCommon.CommElectionTPCAddress, evm.IntraBlockState(), electionStakeTablePrefix)

	gas = gasByteMapReplace(len(key), ttCommon.HashLength)
	if !contract.UseGas(gas) {
		c.logger.Info("incoming bid: out of gas, sender", "sender", contract.Caller().Hex())
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

func (c *commElectionR2) abiGetAvailableStake(evm *vm.EVM, contract *vm.Contract, refundID []byte) ([]byte, error) {
	output := GetAvailableElectionStake(evm.IntraBlockState(), contract.Caller(), refundID)

	return common.BigToHash(output).Bytes(), nil
}

func (c *commElectionR2) abiGetNonce(evm *vm.EVM, key common.Hash) ([]byte, error) {
	nonces := Nonces(evm.IntraBlockState())
	bytes, found := nonces.Find(key.Str())
	if found {
		return common.BytesToHash(bytes).Bytes(), nil
	} else {
		return common.BigToHash(big.NewInt(0)).Bytes(), nil
	}
}

func (c *commElectionR2) verifySigAndIncNonce(ssi *election.SignedStakeInfo, contract *vm.Contract, evm *vm.EVM) error {
	var nonce *big.Int
	palaConfig := evm.ChainConfig().Pala
	s := blocksn.GetSessionFromDifficulty(evm.Context().Difficulty, big.NewInt(int64(evm.Context().BlockNumber)), palaConfig)
	if ssi.Session.Cmp(big.NewInt(int64(s))) != 0 {
		// The client may reference a node which has not caught up the latest status.
		c.logger.Warn("Invalid session in bid from sender", "session", ssi.Session.String(), "expected", s, "from", ssi.StakingAddr.Hex())
		return errors.New("invalid session")
	}

	nonces := Nonces(evm.IntraBlockState())
	key := common.Hash(sha256.Sum256(ssi.PubVoteKey.ToBytes())).Str()
	bytes, found := nonces.Find(key)
	if found {
		nonce = new(big.Int).SetBytes(bytes)
	} else {
		nonce = big.NewInt(0)
	}

	if nonce.Cmp(ssi.Nonce) != 0 {
		// The client may reference a node which has not caught up the latest status.
		c.logger.Warn("Invalid nonce in bid from sender", "nonce", ssi.Nonce.String(), "expected", nonce.String(), "from", ssi.StakingAddr.Hex())
		return errors.New("invalid nonce")
	}

	if !ssi.Verify() {
		c.logger.Warn("Failed to verify bid from sender", "from", ssi.StakingAddr.Hex())
		return errors.New("failed to verify stake info")
	}

	gas := gasByteMapReplace(len(key), ttCommon.HashLength)
	if !contract.UseGas(gas) {
		c.logger.Info("incoming bid: out of gas, sender", "sender", contract.Caller().Hex())
		return vm.ErrOutOfGas
	}
	nonce.Add(nonce, common.Big1)
	nonces.InsertOrReplace(key, nonce.Bytes())
	return nil
}
