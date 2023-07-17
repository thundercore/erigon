package precompile

// #cgo LDFLAGS: -L/usr/local/lib/thunder -lrng -Wl,-rpath,/usr/local/lib/thunder
// #cgo CFLAGS: -I/usr/local/include/thunder
// #include "librng.h"
// #include <stdlib.h>
import "C"
import (
	"math/big"
	"unsafe"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/common"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/params"
)

// NOTE: THIS RNG IS A TEMPORARY VERION ONLY USED FOR FIXING THE BEHAVIOR CHANGE OF `Copy()`
// reference: https://thundercore.atlassian.net/browse/THUNDER-1179
type tempRngForCopyChange struct {
	base
}

func (r *tempRngForCopyChange) RequiredGas(input []byte) uint64 {
	return (params.Sha256BaseGas + params.Sha256PerWordGas*2 + params.Pala2P5SLoad + params.SstoreResetGas) * 6 / 5
}

func (r *tempRngForCopyChange) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	// Adhering to the vault's run implementation
	r.logger.Debug("[RNG_temp] received tx", "from", contract.Caller().Hex(), "len(payload)", len(input))
	output, err := r.call(evm, contract)
	if err != nil {
		r.logger.Debug("[RNG_temp] Failed to generate random", "err", err)
		return nil, vm.ErrExecutionReverted
	}

	return output, nil
}

func (r *tempRngForCopyChange) call(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	return r.abiGenerateRNG(evm), nil
}

func (r *tempRngForCopyChange) abiGenerateRNG(evm *vm.EVM) []byte {
	// Get and store state in statedb
	stateDB := evm.IntraBlockState()

	stateValue := new(uint256.Int)

	stateDB.GetState(ttCommon.RandomTPCAddress, &lookupHash, stateValue)
	r.logger.Debug("[RNG_temp]", "nonce", stateValue.Hex())

	var updatedNonce *uint256.Int
	if stateValue.IsZero() {
		updatedNonce = uint256.NewInt(1)
	} else {
		updatedNonce = stateValue
		updatedNonce.Add(updatedNonce, uint256.NewInt(1))
	}

	stateDB.SetState(ttCommon.RandomTPCAddress, &lookupHash, *updatedNonce)

	if evm.Context().StateRootCal == nil {
		r.logger.Error("[RNG_V3] state root calculator is nil")
		return nil
	}

	root, err := evm.Context().StateRootCal(evm.TxContext())
	if err != nil {
		r.logger.Error("[RNG_temp] calculate state root", "err", err)
		return nil
	}
	evm.IncrementRNGCounter()
	randomNumber := generateRandomV3(*evm.Context().PrevRanDao, updatedNonce.ToBig(), *root)

	r.logger.Debug("[RNG_temp] results", "randomNumber", common.BytesToAddress(randomNumber[:]).Hex())
	return randomNumber[:]
}

type randomV4 struct {
	randomV3
}

func (r *randomV4) RequiredGas(input []byte) uint64 {
	return r.randomV3.RequiredGas(input) * params.RNGGasBumpV4
}

type randomV3 struct {
	base
}

func (r *randomV3) RequiredGas(input []byte) uint64 {
	return (params.Sha256BaseGas + params.Sha256PerWordGas*2 + params.Pala2P5SLoad + params.SstoreResetGas) * 6 / 5
}

func (r *randomV3) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	// Adhering to the vault's run implementation
	r.logger.Debug("[RNG_V3] received tx", "from", contract.Caller().Hex(), "len(payload)", len(input))
	output, err := r.call(evm, contract)
	if err != nil {
		r.logger.Debug("[RNG_V3] Failed to generate random", "err", err)
		return nil, vm.ErrExecutionReverted
	}

	return output, nil
}

func (r *randomV3) call(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	return r.abiGenerateRNG(evm), nil
}

func (r *randomV3) abiGenerateRNG(evm *vm.EVM) []byte {
	// Get and store state in statedb
	stateDB := evm.IntraBlockState()

	nonceToStore := new(uint256.Int)

	stateDB.GetState(ttCommon.RandomTPCAddress, &lookupHash, nonceToStore)

	r.logger.Debug("[RNG_V3]", "nonce", nonceToStore.Hex())

	var updatedNonce *uint256.Int
	if nonceToStore.IsZero() {
		updatedNonce = uint256.NewInt(1)
	} else {
		updatedNonce = nonceToStore
		updatedNonce.Add(updatedNonce, uint256.NewInt(1))
	}
	stateDB.SetState(ttCommon.RandomTPCAddress, &lookupHash, *updatedNonce)

	if evm.Context().StateRootCal == nil {
		r.logger.Error("[RNG_V3] state root calculator is nil")
		return nil
	}

	root, err := evm.Context().StateRootCal(evm.TxContext())
	if err != nil {
		r.logger.Error("[RNG_V3] calculate state root", "err", err)
		return nil
	}
	evm.IncrementRNGCounter()
	randomNumber := generateRandomV3(*evm.Context().PrevRanDao, updatedNonce.ToBig(), *root)

	r.logger.Debug("[RNG_V3] results", "randomNumber", common.BytesToAddress(randomNumber[:]).Hex(), "root", common.BytesToHash(root.Bytes()[:]).Hex(),
		"digest", common.BytesToHash(evm.Context().PrevRanDao.Bytes()[:]).Hex(), "nonce", updatedNonce.Hex())
	return randomNumber[:]
}

type random2P5 struct {
	random
}

func (r *random2P5) RequiredGas(input []byte) uint64 {
	return params.Sha256BaseGas + params.Sha256PerWordGas*2 + params.Pala2P5SLoad + params.SstoreResetGas
}

type random struct {
	base
}

var (
	// just store nonce at location 0
	lookupHash = common.Hash{}
)

// Gas cost set to sha3 hash gas cost for this function call.
func (r *random) RequiredGas(input []byte) uint64 {
	return params.Sha256BaseGas + params.Sha256PerWordGas*2 + params.SloadGas + params.SstoreResetGas
}

// Run the TPC
func (r *random) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	// Adhering to the vault's run implementation
	r.logger.Debug("[RNG_V1] received tx", "from", contract.Caller().Hex(), "len(payload)", len(input))
	output, err := r.call(evm, contract)
	if err != nil {
		r.logger.Debug("[RNG_V1] Failed to generate random", "err", err)
		return nil, vm.ErrExecutionReverted
	}

	return output, nil
}

func (r *random) call(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	return r.abiGenerateRNG(evm), nil
}

func (r *random) abiGenerateRNG(evm *vm.EVM) []byte {
	// Get and store state in statedb
	stateDB := evm.IntraBlockState()

	nonceToStore := new(uint256.Int)

	stateDB.GetState(ttCommon.RandomTPCAddress, &lookupHash, nonceToStore)
	r.logger.Debug("[RNG_V1]", "nonce", nonceToStore.Hex())

	var updatedNonce *uint256.Int
	if nonceToStore.IsZero() {
		updatedNonce = uint256.NewInt(1)
	} else {
		updatedNonce = nonceToStore
		updatedNonce.Add(updatedNonce, uint256.NewInt(1))
	}
	stateDB.SetState(ttCommon.RandomTPCAddress, &lookupHash, *updatedNonce)
	randomNumber := generateRandomV1(*evm.Context().PrevRanDao, updatedNonce.ToBig())

	r.logger.Debug("[RNG_V1] results", "randomNumber", common.BytesToAddress(randomNumber[:]).Hex())
	return randomNumber[:]
}

func generateRandomV1(mixDigest common.Hash, updatedNonce *big.Int) []byte {
	digest := C.GoSlice{
		data: C.CBytes(mixDigest.Bytes()),
		len:  C.GoInt(len(mixDigest.Bytes())),
		cap:  C.GoInt(len(mixDigest.Bytes())),
	}

	nonce := C.GoSlice{
		data: C.CBytes(updatedNonce.Bytes()),
		len:  C.GoInt(len(updatedNonce.Bytes())),
		cap:  C.GoInt(len(updatedNonce.Bytes())),
	}

	retBytes := C.RandomV1(digest, nonce)
	randomNumber := C.GoBytes(retBytes, 32)

	C.free(unsafe.Pointer(digest.data))
	C.free(unsafe.Pointer(nonce.data))

	return randomNumber
}

func generateRandomV3(mixDigest common.Hash, updatedNonce *big.Int, intermediateRoot common.Hash) []byte {
	digest := C.GoSlice{
		data: C.CBytes(mixDigest.Bytes()),
		len:  C.GoInt(len(mixDigest.Bytes())),
		cap:  C.GoInt(len(mixDigest.Bytes())),
	}

	nonce := C.GoSlice{
		data: C.CBytes(updatedNonce.Bytes()),
		len:  C.GoInt(len(updatedNonce.Bytes())),
		cap:  C.GoInt(len(updatedNonce.Bytes())),
	}

	root := C.GoSlice{
		data: C.CBytes(intermediateRoot.Bytes()),
		len:  C.GoInt(len(intermediateRoot.Bytes())),
		cap:  C.GoInt(len(intermediateRoot.Bytes())),
	}

	retBytes := C.RandomV3(digest, nonce, root)
	randomNumber := C.GoBytes(retBytes, 32)

	C.free(unsafe.Pointer(digest.data))
	C.free(unsafe.Pointer(nonce.data))
	C.free(unsafe.Pointer(root.data))

	return randomNumber
}
