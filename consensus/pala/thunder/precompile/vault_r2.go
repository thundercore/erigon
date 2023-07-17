package precompile

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/bls"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/election"
	"github.com/ledgerwatch/erigon/core/vm"
)

func init() {
	{
		_abi, err := abi.JSON(strings.NewReader(vaultR2ABIjson))
		if err != nil {
			debug.Fatal("could not parse vault abi")
		}
		VaultR2ABI = _abi
	}
}

type vaultR2 struct {
	base
}

// vaultR2ABIjson is created by https://remix.ethereum.org with contract like that
//
//	contract Vault {
//	   function createAccount(address operator, bytes32 keyHash) payable { }
//	   function withdraw(bytes32 keyHash, uint amount) external { }
//	   function deposit(bytes32 keyHash) external payable { }
//	   function bid(address rewardAddress, uint stake, uint gasPrice, bytes votePubKey, uint session, uint nonce, bytes sig) external { }
//	   function changeOperator(bytes32 keyHash, address operator) external { }
//	   function getBalance(bytes32 keyHash) view returns(uint) { }
//	   function getOwner(bytes32 keyHash) view returns(address) { }
//	   function getOperator(bytes32 keyHash) view returns(address) { }
//	   function getAvailableBalance(bytes32 keyHash) view returns(int) { }
//	   function getNonce(bytes32 key) view returns(uint) {}
//	}
var vaultR2ABIjson = `
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			},
			{
				"name": "amount",
				"type": "uint256"
			}
		],
		"name": "withdraw",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
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
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"name": "getAvailableBalance",
		"outputs": [
			{
				"name": "",
				"type": "int256"
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
		"constant": false,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			},
			{
				"name": "operator",
				"type": "address"
			}
		],
		"name": "changeOperator",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"name": "getBalance",
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
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"name": "getOperator",
		"outputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"name": "deposit",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"name": "getOwner",
		"outputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "operator",
				"type": "address"
			},
			{
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"name": "createAccount",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	}
]
`
var VaultR2ABI abi.ABI

func (v *vaultR2) RequiredGas(input []byte) uint64 {
	// NOTE: We set 0 here and comsuming gas in Run() since we have vm.Contract to use
	return 0
}

func (v *vaultR2) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	v.logger.Debug("Run", "from", contract.Caller().Hex(), "len(data)", len(input))
	if len(input) < 4 {
		v.logger.Debug("Reverting on bad input")
		return nil, vm.ErrExecutionReverted
	}

	id := input[:4]
	arg := input[4:]

	method, err := VaultR2ABI.MethodById(id)
	if err != nil {
		v.logger.Debug("Method not found", "err", err)
		return nil, vm.ErrExecutionReverted
	}

	output, err := v.call(method, arg, evm, contract)
	if err != nil {
		v.logger.Debug("Execution failed", "err", err)
		return nil, vm.ErrExecutionReverted
	}

	return output, nil
}

func (v *vaultR2) call(method *abi.Method, input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	v.logger.Debug("Call", "method", method.Name)
	switch method.Name {
	case "deposit":
		var arg common.Hash

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}
		return nil, v.abiDeposit(evm, contract, arg)
	case "withdraw":
		var arg struct {
			KeyHash common.Hash
			Amount  *big.Int
		}

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}

		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}

		return nil, v.abiWithdraw(evm, contract, arg.KeyHash, arg.Amount)

	case "createAccount":
		var arg struct {
			Operator common.Address
			KeyHash  common.Hash
		}

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}

		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}

		return nil, v.abiCreateAccount(evm, contract, arg.Operator, arg.KeyHash)

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
			v.logger.Debug("Failed to parse vote key", "pubkey", pubkey, "err", err)
			return nil, err
		}

		sig, err := bls.SignatureFromBytes(arg.Sig)
		if err != nil {
			v.logger.Warn("Failed to get signature", "err", err, "sender", arg.RewardAddress.Hex())
			return nil, err
		}

		rewardAddress := arg.RewardAddress
		session := blocksn.GetSessionFromDifficulty(evm.Context().Difficulty, big.NewInt(int64(evm.Context().BlockNumber)), evm.ChainConfig().Pala)
		if election.BurnReward.GetValueHardforkAtSession(evm.ChainConfig().Pala.Hardforks, int64(session)) {
			rewardAddress = common.Address{}
		}
		var msg = &election.SignedStakeInfo{
			StakeInfo: election.StakeInfo{
				StakeMsg: election.StakeMsg{
					Stake:      arg.Stake,
					Coinbase:   rewardAddress,
					GasPrice:   arg.GasPrice,
					PubVoteKey: pubkey,
				},
			},
			Session: arg.Session,
			Nonce:   arg.Nonce,
			Sig:     sig,
		}

		return nil, v.abiBid(evm, contract, msg)
	case "changeOperator":
		var arg struct {
			Operator common.Address
			KeyHash  common.Hash
		}

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}

		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}

		return nil, v.abiChangeOperator(evm, contract, arg.KeyHash, arg.Operator)

	case "getBalance":
		var arg common.Hash

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}
		return v.abiGetBalance(evm, contract, arg)

	case "getOwner":
		var arg common.Hash

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}
		return v.abiGetOwner(evm, contract, arg)

	case "getOperator":
		var arg common.Hash

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}
		return v.abiGetOperator(evm, contract, arg)

	case "getAvailableBalance":
		var arg common.Hash

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}
		return v.abiGetAvailableBalance(evm, contract, arg)
	case "getNonce":
		var arg common.Hash

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}

		return v.abiGetNonce(evm, contract, arg)
	default:
		return nil, fmt.Errorf("no such method")
	}
}

func (v *vaultR2) abiCreateAccount(evm *vm.EVM, contract *vm.Contract,
	operationalAccount common.Address, keyHash common.Hash) error {
	msgSender := contract.CallerAddress
	v.logger.Debug("Create account", "account", operationalAccount.Hex(), "keyHash", keyHash.Hex(), "from", msgSender.Hex())

	balanceTable := Balances(evm.IntraBlockState())
	key := keyHash.Str()

	gas := gasByteMapFind(ttCommon.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	_, exists := balanceTable.Find(key)

	if exists {
		v.logger.Debug("Already exists", "keyHash", keyHash.Hex())
		return fmt.Errorf("already registered")
	}

	// note balance is 0 and you will be paying for storing these 0s
	// this makes gas computation for deposit easier.
	gas = gasByteMapInsert(ttCommon.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	entry := NewVaultBalanceEntry(msgSender, operationalAccount)

	entry.Balance.Set(contract.Value().ToBig())
	balanceTable.InsertOrReplace(key, entry.ToBytes())

	return nil
}

func (v *vaultR2) abiDeposit(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) error {
	v.logger.Debug("Deposit", "keyHash", keyHash.Hex(), "from", contract.CallerAddress.Hex(), "value", contract.Value().String())

	key := keyHash.Str()

	gas := gasByteMapFind(ttCommon.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	balanceTable := Balances(evm.IntraBlockState())
	entry, err := getVaultBalanceFromTable(balanceTable, key)

	if err != nil {
		v.logger.Debug("no entry")
		return err
	}

	gas = gasByteMapReplace(ttCommon.HashLength, balanceEnd-balanceOffset)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	v.logger.Debug("Add balance", "amount", contract.Value().String())
	entry.Balance.Add(entry.Balance, contract.Value().ToBig())
	balanceTable.InsertOrReplaceEntry(key, entry)

	return nil
}

func (v *vaultR2) abiWithdraw(evm *vm.EVM, contract *vm.Contract,
	keyHash common.Hash, amount *big.Int) error {
	v.logger.Debug("Withdraw", "keyHash", keyHash.Hex(), "amount", amount.String())
	msgSender := contract.CallerAddress
	key := keyHash.Str()

	gas := gasByteMapFind(ttCommon.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	balanceTable := Balances(evm.IntraBlockState())
	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return err
	}

	// only operator and owner account allowed to withdraw
	if entry.parentAccount != msgSender && entry.operationalAccount != msgSender {
		return fmt.Errorf("sender Account mismatch")
	}

	if entry.Balance.Cmp(amount) < 0 {
		return vm.ErrInsufficientBalance
	}

	entry.Balance.Sub(entry.Balance, amount)

	gas = gasByteMapReplace(ttCommon.HashLength, balanceEnd-balanceOffset)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	balanceTable.InsertOrReplaceEntry(key, entry)

	// CanTransfer checks for sufficient transfer. This should never happen assuming all accounting
	// is correct in Vault implementation.

	uint256Amount := new(uint256.Int)
	overflow := uint256Amount.SetFromBig(amount)

	if overflow || !evm.Context().CanTransfer(evm.IntraBlockState(), ttCommon.VaultTPCAddress, uint256Amount) {
		debug.Bug("Cannot withdraw from vault")
	}

	evm.Context().Transfer(evm.IntraBlockState(), ttCommon.VaultTPCAddress, entry.parentAccount, uint256Amount, false)

	return nil
}

func (v *vaultR2) abiBid(evm *vm.EVM, contract *vm.Contract,
	signedStakeInfo *election.SignedStakeInfo) error {
	msgSender := contract.CallerAddress
	balanceTable := Balances(evm.IntraBlockState())

	keyHash := common.Hash(sha256.Sum256(signedStakeInfo.PubVoteKey.ToBytes()))
	key := keyHash.Str()

	v.logger.Debug("Add bid", "keyHash", keyHash.Hex())
	gas := gasByteMapFind(ttCommon.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		v.logger.Debug("Account not found")
		return err
	}

	if entry.operationalAccount != msgSender {
		v.logger.Debug("Invalid operator account", "operationalAccount", entry.operationalAccount.Hex(), "msgSender", msgSender.Hex())
		return fmt.Errorf("operation Account mismatch")
	}

	// use refund(keyHash) as our refund callback
	refundID, err := VaultR2ABI.Pack("deposit", keyHash)
	if err != nil {
		v.logger.Debug("packing failed")
		return errors.New("pack failed")
	}

	// calculate the required amount of thunder to transfer
	stakeQueryMethod := ElectionR2ABI.Methods["getAvailableStake"]
	ret, err := evmABICall(evm, contract, ttCommon.CommElectionTPCAddress, big.NewInt(0), gasRead, &stakeQueryMethod, refundID)
	if err != nil {
		v.logger.Debug("Get available stake failed")
		return err
	}

	bidBalance := common.BytesToHash(ret).Big()

	requiredValue := big.NewInt(0).Sub(signedStakeInfo.Stake, bidBalance)
	if requiredValue.Sign() < 0 {
		requiredValue.SetInt64(0)
	}

	if entry.Balance.Cmp(requiredValue) < 0 {
		v.logger.Debug("Insufficient balance", "balance", entry.Balance.String(), "required", requiredValue.String())
		return vm.ErrInsufficientBalance
	}

	gas = gasByteMapReplace(ttCommon.HashLength, balanceEnd-balanceOffset)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	// update our accounting
	entry.Balance.Sub(entry.Balance, requiredValue)
	balanceTable.InsertOrReplaceEntry(key, entry)

	bidMethod := ElectionR2ABI.Methods["bid"]
	gasLimit := gasBid
	palaConfig := evm.ChainConfig().Pala
	s := blocksn.GetSessionFromDifficulty(evm.Context().Difficulty, big.NewInt(int64(evm.Context().BlockNumber)), palaConfig)
	if palaConfig.VaultGasUnlimited.GetValueHardforkAtSession(palaConfig.Hardforks, int64(s)) {
		gasLimit = contract.Gas
	}
	_, err = evmABICall(evm, contract, ttCommon.CommElectionTPCAddress, requiredValue, gasLimit, &bidMethod,
		signedStakeInfo.Coinbase, &signedStakeInfo.Stake, &signedStakeInfo.GasPrice, signedStakeInfo.PubVoteKey.ToBytes(), signedStakeInfo.Session, signedStakeInfo.Nonce, signedStakeInfo.Sig.ToBytes(), refundID)

	v.logger.Debug("Bid finished", "err", err)
	return err
}

func (v *vaultR2) abiChangeOperator(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash, operator common.Address) error {
	balanceTable := Balances(evm.IntraBlockState())
	key := keyHash.Str()

	v.logger.Debug("ChangeOperator", "keyHash", keyHash.Hex(), "operator", operator.Hex())

	gas := gasByteMapFind(ttCommon.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return err
	}

	if contract.Caller() != entry.parentAccount {
		return fmt.Errorf("parentAccount mismatch")
	}

	gas = gasByteMapReplace(ttCommon.HashLength, opEnd-opOffset)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	entry.operationalAccount = operator
	balanceTable.InsertOrReplaceEntry(key, entry)

	return nil
}

func (v *vaultR2) abiGetBalance(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) ([]byte, error) {
	balanceTable := Balances(evm.IntraBlockState())
	key := keyHash.Str()

	gas := gasByteMapFind(ttCommon.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return nil, vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return nil, err
	}
	return common.BigToHash(entry.Balance).Bytes(), nil
}

func (v *vaultR2) abiGetOwner(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) ([]byte, error) {
	balanceTable := Balances(evm.IntraBlockState())
	key := keyHash.Str()

	gas := gasByteMapFind(ttCommon.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return nil, vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return nil, err
	}
	return entry.parentAccount.Hash().Bytes(), nil
}

func (v *vaultR2) abiGetOperator(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) ([]byte, error) {
	balanceTable := Balances(evm.IntraBlockState())
	key := keyHash.Str()

	gas := gasByteMapFind(ttCommon.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return nil, vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return nil, err
	}
	return entry.operationalAccount.Hash().Bytes(), nil
}

func (v *vaultR2) abiGetAvailableBalance(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) ([]byte, error) {
	balanceTable := Balances(evm.IntraBlockState())
	key := keyHash.Str()

	gas := gasByteMapFind(ttCommon.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return nil, vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		v.logger.Debug("Account not found")
		return nil, err
	}

	// use refund(keyHash) as our refund callback
	refundID, err := VaultR2ABI.Pack("deposit", keyHash)
	if err != nil {
		v.logger.Debug("Packing failed")
		return nil, errors.New("pack failed")
	}

	// forward call the getAvailableStake
	stakeQueryMethod := ElectionR2ABI.Methods["getAvailableStake"]
	ret, err := evmABICall(evm, contract, ttCommon.CommElectionTPCAddress, big.NewInt(0), gasRead, &stakeQueryMethod, refundID)
	if err != nil {
		v.logger.Debug("Get available stake failed")
		return nil, err
	}

	// add our own balance
	bidBalance := common.BytesToHash(ret).Big()

	retValue := big.NewInt(0).Add(entry.Balance, bidBalance)

	return common.BigToHash(retValue).Bytes(), nil
}

func (v *vaultR2) abiGetNonce(evm *vm.EVM, contract *vm.Contract, key common.Hash) ([]byte, error) {
	method := ElectionR2ABI.Methods["getNonce"]
	ret, err := evmABICall(evm, contract, ttCommon.CommElectionTPCAddress, big.NewInt(0), gasRead, &method, key)
	if err != nil {
		v.logger.Warn("Failed to get nonce")
		return nil, err
	}
	nonce := common.BytesToHash(ret).Big()
	return common.BigToHash(nonce).Bytes(), nil
}
