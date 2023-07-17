package precompile

import (
	"math/big"

	"github.com/ledgerwatch/log/v3"

	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/thunder/hardfork"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/core/vm"
)

var (
	logger = log.New("package", "thunder/precompile")

	_commElect   = &commElection{base: base{logger: logger.New("contract", "commElection")}}
	_commElectR2 = &commElectionR2{base: base{logger: logger.New("contract", "commElectionR2")}}
	_commElectR3 = &commElectionR3{commElectionR2: commElectionR2{base: base{logger: logger.New("contract", "commElectionR3")}}}

	_vault   = &vault{base{logger: logger.New("contract", "Vault")}}
	_vaultR2 = &vaultR2{base: base{logger: logger.New("contract", "VaultR2")}}
	_vaultR3 = &vaultR3{vaultR2: vaultR2{base: base{logger: logger.New("contract", "VaultR3")}}}

	_random     = &random{base: base{logger: logger.New("contract", "Random")}}
	_random2P5  = &random2P5{random: random{base: base{logger: logger.New("contract", "Random2P5")}}}
	_randomR3   = &randomV3{base: base{logger: logger.New("contract", "RandomR3")}}
	_randomR4   = &randomV4{randomV3: randomV3{base: base{logger: logger.New("contract", "RandomR4")}}}
	_randomTemp = &tempRngForCopyChange{base: base{logger: logger.New("contract", "RandomTemp")}}

	_blocksn = &thunderBlockSn{base: base{logger: logger.New("contract", "BlockSn")}}

	hardforkActiveTPC = map[common.Address]vm.PrecompiledThunderContract{
		ttCommon.CommElectionTPCAddress: _commElect,
		ttCommon.VaultTPCAddress:        _vault,
		ttCommon.RandomTPCAddress:       _random,
		ttCommon.BlockSnTPCAddress:      _blocksn,
	}

	IsRNGActive = hardfork.NewBoolHardforkConfig(
		"trustedRNG.rngActive",
		"Trusted RNG hardfor activation",
	)
	IsBlockSnGetterActive = hardfork.NewBoolHardforkConfig(
		"precompiled.blockSnGetterActive",
		"Session getter hardfork activation",
	)
	VaultVersion = hardfork.NewStringHardforkConfig(
		"precompiled.vaultVersion",
		"Vault version",
	)
	ElectionVersion = hardfork.NewStringHardforkConfig(
		"committee.electVersion",
		"Committee election version",
	)
)

type base struct {
	logger log.Logger
}

func getPrecompiledContract(evm *vm.EVM) map[common.Address]vm.PrecompiledThunderContract {
	r := map[common.Address]vm.PrecompiledThunderContract{
		ttCommon.CommElectionTPCAddress: _commElect,
		ttCommon.VaultTPCAddress:        _vault,
	}

	session := blocksn.GetSessionFromDifficulty(evm.Context().Difficulty, big.NewInt(int64(evm.Context().BlockNumber)), evm.ChainConfig().Pala)
	if IsRNGActive.GetValueHardforkAtBlock(evm.ChainConfig().Pala.Hardforks, int64(evm.Context().BlockNumber)) {
		rngVersion := evm.ChainConfig().Pala.RNGVersion.GetValueHardforkAtSession(evm.ChainConfig().Pala.Hardforks, int64(session))

		if rngVersion == "v4" {
			r[ttCommon.RandomTPCAddress] = _randomR4
		} else if rngVersion == "v3" {
			r[ttCommon.RandomTPCAddress] = _randomR3
		} else if rngVersion == "testnet-fnx-rng-broken" {
			r[ttCommon.RandomTPCAddress] = _randomTemp
		} else if evm.ChainConfig().Pala.IsPala2P5GasTable(session) {
			r[ttCommon.RandomTPCAddress] = _random2P5
		} else {
			r[ttCommon.RandomTPCAddress] = _random
		}
	}

	if evm.ChainConfig().Pala.ShouldVerifyBid(session) {
		r[ttCommon.CommElectionTPCAddress] = _commElectR2
		r[ttCommon.VaultTPCAddress] = _vaultR2

	}

	if VaultVersion.GetValueHardforkAtSession(evm.ChainConfig().Pala.Hardforks, int64(session)) == "r3" {
		r[ttCommon.VaultTPCAddress] = _vaultR3
	}

	if ElectionVersion.GetValueHardforkAtSession(evm.ChainConfig().Pala.Hardforks, int64(session)) == "r3" {
		r[ttCommon.CommElectionTPCAddress] = _commElectR3
	}

	if IsBlockSnGetterActive.GetValueHardforkAtSession(evm.ChainConfig().Pala.Hardforks, int64(session)) {
		r[ttCommon.BlockSnTPCAddress] = _blocksn
	}

	return r
}

func Init() {
	vm.PrecompiledThunderContracts = getPrecompiledContract
	vm.ThunderPrecompiledContracts = hardforkActiveTPC
}
