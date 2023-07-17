package precompile

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/accounts/abi"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/params"
)

var VaultR3ABI abi.ABI

func init() {
	{
		_abi, err := abi.JSON(strings.NewReader(VaultR3ABIjson))
		if err != nil {
			debug.Fatal("could not parse vault abi")
		}
		VaultR3ABI = _abi
	}
}

type vaultR3 struct {
	vaultR2
}

// vaultR3ABIjson is created by https://remix.ethereum.org with contract like that
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
//		  function setBidAmount(bytes32 keyHash, uint256 amount) external {}
//		  function getBidAmount(bytes32 keyHash) view external returns (uint256)  {}
//	}
var VaultR3ABIjson = `
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
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"name": "getBidAmount",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "keyHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "amount",
				"type": "uint256"
			}
		],
		"name": "setBidAmount",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
`

func encodeKeyToHash(key string) common.Hash {
	return common.Hash(sha256.Sum256([]byte(key)))
}

const bidAmountKey = "bidAmount:"

func (v *vaultR3) RequiredGas(input []byte) uint64 {
	id := input[:4]

	method, err := VaultR3ABI.MethodById(id)
	if err != nil {
		return 0
	}
	switch method.Name {
	case "setBidAmount":
		return params.SstoreSetGas
	case "getBidAmount":
		return params.Pala2P5SLoad
	default:
		return 0
	}
}

func (v *vaultR3) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	v.logger.Debug("Run", "from", contract.Caller().Hex(), "len(data)", len(input))
	if len(input) < 4 {
		v.logger.Debug("Reverting on bad input")
		return nil, vm.ErrExecutionReverted
	}

	id := input[:4]
	arg := input[4:]

	method, err := VaultR3ABI.MethodById(id)
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

func (v *vaultR3) call(method *abi.Method, input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	v.logger.Debug("Call", "method", method.Name)
	switch method.Name {
	case "setBidAmount":
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
		return nil, v.abiSetBidAmount(evm, contract, arg.KeyHash, arg.Amount)
	case "getBidAmount":
		var arg common.Hash

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}
		return v.abiGetBidAmount(evm, contract, arg)
	default:
		return v.vaultR2.call(method, input, evm, contract)
	}
}

func (v *vaultR3) abiSetBidAmount(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash, amount *big.Int) error {
	v.logger.Debug("SetBidAmount", "amount", amount)

	msgSender := contract.CallerAddress
	key := keyHash.Str()

	db := evm.IntraBlockState()

	balanceTable := Balances(evm.IntraBlockState())
	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return err
	}

	// only operator and owner account allowed to withdraw
	if entry.parentAccount != msgSender && entry.operationalAccount != msgSender {
		return fmt.Errorf("permission denied, only operator or owner account allowed to setBidAmount")
	}

	stateKey := encodeKeyToHash(bidAmountKey + keyHash.Hex())
	stateValue := new(uint256.Int)

	overflow := stateValue.SetFromBig(amount)
	if overflow {
		return fmt.Errorf("failed to convert amount to uint256, overflow")
	}

	db.SetState(ttCommon.VaultTPCAddress, &stateKey, *stateValue)

	return nil
}

func (v *vaultR3) abiGetBidAmount(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) ([]byte, error) {
	v.logger.Debug("GetBidAmount", "keyHash", keyHash.Hex())

	db := evm.IntraBlockState()

	stateKey := encodeKeyToHash(bidAmountKey + keyHash.Hex())
	stateValue := new(uint256.Int)

	db.GetState(ttCommon.VaultTPCAddress, &stateKey, stateValue)
	outAmountBytes32 := new(uint256.Int).SetBytes(stateValue.Bytes()).Bytes32()

	ret := []byte{}
	ret = append(ret, outAmountBytes32[:]...)

	return ret, nil
}
