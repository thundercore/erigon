package precompile

import (
	"math/big"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/params"
)

type thunderBlockSn struct {
	base
}

func (r *thunderBlockSn) RequiredGas(input []byte) uint64 {
	return params.Pala2P5Calls
}

func (r *thunderBlockSn) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	// Adhering to the vault's run implementation
	r.logger.Debug("Run", "from", contract.Caller().Hex(), "len(data)", len(input))
	output, err := r.call(evm, contract)
	if err != nil {
		r.logger.Debug("Get consensus session execution failed", "err", err)
		return nil, vm.ErrExecutionReverted
	}

	return output, nil
}

func (r *thunderBlockSn) call(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	palaConfig := evm.ChainConfig().Pala
	blocksn := blocksn.GetBlockSnFromDifficulty(evm.Context().Difficulty, big.NewInt(int64(evm.Context().BlockNumber)), palaConfig)

	uint256Sess := new(uint256.Int).SetUint64(uint64(blocksn.Epoch.Session))
	uint256E := new(uint256.Int).SetUint64(uint64(blocksn.Epoch.E))
	uint256S := new(uint256.Int).SetUint64(uint64(blocksn.S))

	sessByte32 := uint256Sess.Bytes32()
	eByte32 := uint256E.Bytes32()
	sByte32 := uint256S.Bytes32()

	ret := []byte{}
	ret = append(ret, sessByte32[:]...)
	ret = append(ret, eByte32[:]...)
	ret = append(ret, sByte32[:]...)

	return ret[:], nil
}
