package commands

import (
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/types"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/core/vm/stack"
)

var (
	errExecutionReverted = fmt.Errorf("execution reverted")
)

type VmCall struct {
	From           common.Address
	To             *common.Address `rlp:"nil"`
	Value          *big.Int        `rlp:"nil"`
	Error          *string         `rlp:"nil"`
	Reason         *string         `rlp:"nil"`
	OpCode         string
	Indices        []uint64
	Gas            uint64
	GasUsed        uint64
	GasIn          uint64 `rlp:"-"`
	GasInstrcution uint64 `rlp:"-"`
}

type ttBlockTracer struct {
	transfers  []*VmCall
	indexStack []int // push when start, pop when end
	index      uint64
	descending bool
	env        vm.VMInterface
}

func (t *ttBlockTracer) CaptureStart(env vm.VMInterface, from common.Address, to common.Address, precompile bool, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {
	index := len(t.transfers)
	op := vm.CALL.String()
	if create {
		op = vm.CREATE.String()
	}

	if t.env == nil {
		t.env = env
	}

	palaConfig := env.ChainConfig().Pala
	session := blocksn.GetSessionFromDifficulty(env.Context().Difficulty, big.NewInt(int64(env.Context().BlockNumber)), palaConfig)
	rules := env.ChainConfig().Rules(env.Context().BlockNumber, 0, session)

	// Compute intrinsic gas
	isHomestead := rules.IsHomestead
	isIstanbul := rules.IsIstanbul
	isShanghai := rules.IsShanghai
	intrinsicGas, err := core.IntrinsicGas(input, types.AccessList{}, create, isHomestead, isIstanbul, isShanghai)
	if err != nil {
		return
	}
	t.transfers = append(t.transfers, &VmCall{
		From:           from,
		To:             &to,
		Value:          new(big.Int).Set(value.ToBig()),
		OpCode:         op,
		Gas:            gas + intrinsicGas,
		GasInstrcution: intrinsicGas,
	})
	t.indexStack = append(t.indexStack, index)
}

func (t *ttBlockTracer) captureCall(pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *stack.Stack, contract *vm.Contract, depth int, err error) error {
	to := common.BigToAddress(stack.Back(1).ToBig())
	v := &VmCall{
		From:           contract.Address(),
		To:             &to,
		Indices:        append(t.top().Indices, t.index),
		OpCode:         op.String(),
		GasIn:          gas,
		GasInstrcution: cost,
	}
	if op != vm.DELEGATECALL && op != vm.STATICCALL {
		v.Value = new(big.Int).Set(stack.Back(2).ToBig())
	}

	t.push(v)
	t.descending = true
	return nil
}

func (t *ttBlockTracer) captureCreate(pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *stack.Stack, contract *vm.Contract, depth int, err error) error {
	t.push(&VmCall{
		From:           contract.Address(),
		Value:          new(big.Int).Set(stack.Back(0).ToBig()),
		Indices:        append(t.top().Indices, t.index),
		OpCode:         op.String(),
		GasIn:          gas,
		GasInstrcution: cost,
	})
	t.descending = true
	return nil
}

func (t *ttBlockTracer) top() *VmCall {
	index := t.indexStack[len(t.indexStack)-1]
	return t.transfers[index]
}

func (t *ttBlockTracer) pop() {
	p := t.top()
	t.indexStack = t.indexStack[:len(t.indexStack)-1]
	if len(p.Indices) != 0 {
		t.index = p.Indices[len(p.Indices)-1] + 1
	}
}

func (t *ttBlockTracer) push(v *VmCall) {
	index := len(t.transfers)
	t.transfers = append(t.transfers, v)
	t.indexStack = append(t.indexStack, index)
	t.index = 0
}

func (t *ttBlockTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if err != nil {
		t.CaptureFault(pc, op, gas, cost, scope, depth, err)
		return
	}
	if t.descending {
		p := t.top()
		if len(p.Indices)+1 == depth {
			p.Gas = gas
		}
		t.descending = false
	}
	if op == vm.REVERT {
		t.CaptureFault(pc, op, gas, cost, scope, depth, errExecutionReverted)
		return
	} else if op == vm.CALL || op == vm.DELEGATECALL || op == vm.CALLCODE || op == vm.STATICCALL {
		t.captureCall(pc, op, gas, cost, scope.Memory, scope.Stack, scope.Contract, depth, err)
		return
	} else if op == vm.CREATE || op == vm.CREATE2 {
		t.captureCreate(pc, op, gas, cost, scope.Memory, scope.Stack, scope.Contract, depth, err)
		return
	} else if op == vm.SELFDESTRUCT {
		to := common.BigToAddress(scope.Stack.Back(0).ToBig())
		balance := t.env.IntraBlockState().GetBalance(scope.Contract.Address())

		t.push(&VmCall{
			From:    scope.Contract.Address(),
			To:      &to,
			Value:   balance.ToBig(),
			Indices: append(t.top().Indices, t.index),
			OpCode:  vm.OpCode(vm.SELFDESTRUCT).String(),
			Gas:     cost,
			GasUsed: cost,
		})
		t.pop()
	} else if depth == len(t.indexStack)-1 {
		parent := t.top()
		if parent.OpCode == vm.CREATE.String() || parent.OpCode == vm.CREATE2.String() {
			addressInt := scope.Stack.Back(0)
			if parent.Gas != 0 {
				parent.GasUsed = parent.GasIn - parent.GasInstrcution - gas
			}

			if addressInt.Sign() != 0 {
				to := common.BigToAddress(addressInt.ToBig())
				parent.To = &to
			} else if parent.Error == nil {
				s := "internal failure"
				parent.Error = &s
			}
		} else {
			if parent.Gas != 0 {
				parent.GasUsed = parent.GasIn - parent.GasInstrcution + parent.Gas - gas
				ret := scope.Stack.Back(0)
				if ret.Sign() == 0 && parent.Error == nil {
					s := "internal failure"
					parent.Error = &s
				}
			}
		}
		t.pop()
	}
}

func (t *ttBlockTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
	// fault can be invalid instruction or out of gas.
	if t.top().Error != nil {
		return
	}

	r := err.Error()
	t.top().Error = &r
}

func (t *ttBlockTracer) CaptureEnd(output []byte, usedGas uint64, err error) {
	parent := t.top()
	if err != nil {
		r := err.Error()
		if err == vm.ErrExecutionReverted && len(output) > 64+4 {
			strLen := common.BytesToHash(output[4+32 : 4+64]).Big().Uint64()
			// Using the length and known offset, extract and convert the revert reason
			var reason string
			if uint64(len(output)) < 4+64+strLen {
				reason = "UNKNOWN_REVERT_REASON"
			} else {
				reason = string(output[4+64 : 4+64+strLen])
			}
			parent.Reason = &reason
			r = errExecutionReverted.Error()
			//} else {
			// 	debug.Bug("Only size of %d: %x", len(output), output)
		}
		parent.Error = &r
	}

	parent.GasUsed = usedGas + parent.GasInstrcution
	//	parent.GasUsed = gasUsed
	t.pop()
}

func (t *ttBlockTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, precompile bool, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {
}

func (t *ttBlockTracer) CaptureExit(output []byte, usedGas uint64, err error) {
}

func (t *ttBlockTracer) CaptureTxStart(gasLimit uint64) {

}

func (t *ttBlockTracer) CaptureTxEnd(restGas uint64) {

}

func (t *ttBlockTracer) getTransfers() []*VmCall {
	return t.transfers
}

type TranserInTransaction struct {
	Transfers []*VmCall
}
