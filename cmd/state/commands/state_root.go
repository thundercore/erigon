package commands

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	chain2 "github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	datadir2 "github.com/ledgerwatch/erigon-lib/common/datadir"
	"github.com/ledgerwatch/erigon-lib/kv"
	kv2 "github.com/ledgerwatch/erigon-lib/kv/mdbx"
	ttConfig "github.com/ledgerwatch/erigon-lib/thunder/config"
	"github.com/ledgerwatch/erigon-lib/thunder/hardfork"
	"github.com/ledgerwatch/log/v3"
	"github.com/spf13/cobra"

	"github.com/ledgerwatch/erigon/consensus"
	cdb "github.com/ledgerwatch/erigon/consensus/db"
	"github.com/ledgerwatch/erigon/consensus/ethash"
	"github.com/ledgerwatch/erigon/consensus/pala"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/committee"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/precompile"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/eth/ethconfig"
	"github.com/ledgerwatch/erigon/eth/stagedsync"
	"github.com/ledgerwatch/erigon/turbo/services"
	"github.com/ledgerwatch/erigon/turbo/snapshotsync"
	"github.com/ledgerwatch/erigon/turbo/trie"
)

func init() {
	withBlock(stateRootCmd)
	withDataDir(stateRootCmd)
	withChain(stateRootCmd)
	withHardfork(stateRootCmd)
	withCommonConfig(stateRootCmd)
	rootCmd.AddCommand(stateRootCmd)
}

var stateRootCmd = &cobra.Command{
	Use:   "stateroot",
	Short: "Exerimental command to re-execute blocks from beginning and compute state root",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := log.New()
		return StateRoot(genesis, logger, block, datadirCli)
	},
}

func StateRoot(genesis *core.Genesis, logger log.Logger, blockNum uint64, datadir string) error {
	sigs := make(chan os.Signal, 1)
	interruptCh := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		interruptCh <- true
	}()
	dirs := datadir2.New(datadir)
	historyDb, err := kv2.NewMDBX(logger).Path(dirs.Chaindata).Open()
	if err != nil {
		return err
	}
	defer historyDb.Close()
	ctx := context.Background()
	historyTx, err1 := historyDb.BeginRo(ctx)
	if err1 != nil {
		return err1
	}
	defer historyTx.Rollback()

	allSnapshots := snapshotsync.NewRoSnapshots(ethconfig.NewSnapCfg(true, false, true), dirs.Snap)
	defer allSnapshots.Close()
	allSnapshots.OptimisticReopenWithDB(historyDb)
	blockReader := snapshotsync.NewBlockReaderWithSnapshots(allSnapshots, false)

	stateDbPath := filepath.Join(datadir, "staterootdb")
	if _, err = os.Stat(stateDbPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if err = os.RemoveAll(stateDbPath); err != nil {
		return err
	}
	db, err2 := kv2.NewMDBX(logger).Path(stateDbPath).Open()
	if err2 != nil {
		return err2
	}
	defer db.Close()
	chainConfig := genesis.Config
	vmConfig := vm.Config{}

	var engine consensus.Engine = ethash.NewFullFaker()

	if commonConfigFile != "" && hardforkConfigFile != "" {
		dbPath := filepath.Join(dirs.DataDir, "pala")
		setPalaConfig(commonConfigFile, hardforkConfigFile, chainConfig.Pala)
		engine = pala.New(chainConfig, cdb.OpenDatabase(dbPath, logger, false, false))
	}

	interrupt := false
	block := uint64(0)
	var rwTx kv.RwTx
	defer func() {
		rwTx.Rollback()
	}()
	if rwTx, err = db.BeginRw(ctx); err != nil {
		return err
	}
	_, genesisIbs, err4 := genesis.ToBlock("")
	if err4 != nil {
		return err4
	}
	w := state.NewPlainStateWriter(rwTx, nil, 0)
	if err = genesisIbs.CommitBlock(&chain2.Rules{}, w); err != nil {
		return fmt.Errorf("cannot write state: %w", err)
	}
	if err = rwTx.Commit(); err != nil {
		return err
	}
	var tx kv.Tx
	defer func() {
		if tx != nil {
			tx.Rollback()
		}
	}()
	for !interrupt {
		block++
		if block >= blockNum {
			break
		}
		blockHash, err := rawdb.ReadCanonicalHash(historyTx, block)
		if err != nil {
			return err
		}
		var b *types.Block
		b, _, err = blockReader.BlockWithSenders(context.Background(), historyTx, blockHash, block)
		if err != nil {
			return err
		}
		if b == nil {
			log.Debug("empty block", "hash", blockHash.Hex())
			break
		}
		if tx, err = db.BeginRo(ctx); err != nil {
			return err
		}
		if rwTx, err = db.BeginRw(ctx); err != nil {
			return err
		}
		w = state.NewPlainStateWriter(rwTx, nil, block)
		r := state.NewPlainStateReader(tx)
		intraBlockState := state.New(r)
		getHeader := func(hash libcommon.Hash, number uint64) *types.Header {
			return rawdb.ReadHeader(historyTx, hash, number)
		}

		stateRootFn := func() (*libcommon.Hash, error) {
			return stagedsync.CalculateStateRoot(rwTx, dirs.Tmp, engine)
		}

		headerReader := ChainReaderImpl{config: chainConfig, tx: tx, blockReader: blockReader}

		if _, err = runBlock(engine, intraBlockState, w, w, chainConfig, getHeader, b, vmConfig, false, headerReader, stateRootFn); err != nil {
			return fmt.Errorf("block %d: %w", block, err)
		}
		if block+1 == blockNum {
			if err = rwTx.ClearBucket(kv.HashedAccounts); err != nil {
				return err
			}
			if err = rwTx.ClearBucket(kv.HashedStorage); err != nil {
				return err
			}
			if err = stagedsync.PromoteHashedStateCleanly("hashedstate", rwTx, stagedsync.StageHashStateCfg(nil, dirs, false, nil), ctx); err != nil {
				return err
			}
			var root libcommon.Hash
			root, err = trie.CalcRoot("genesis", rwTx)
			if err != nil {
				return err
			}
			fmt.Printf("root for block %d=[%x]\n", block, root)
		}
		if block%1000 == 0 {
			log.Info("Processed", "blocks", block)
		}
		// Check for interrupts
		select {
		case interrupt = <-interruptCh:
			fmt.Println("interrupted, please wait for cleanup...")
		default:
		}
		tx.Rollback()
		if err = rwTx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

type ChainReaderImpl struct {
	config      *chain2.Config
	tx          kv.Getter
	blockReader services.FullBlockReader
}

func NewChainReaderImpl(config *chain2.Config, tx kv.Getter, blockReader services.FullBlockReader) *ChainReaderImpl {
	return &ChainReaderImpl{config, tx, blockReader}
}

func (cr ChainReaderImpl) Config() *chain2.Config       { return cr.config }
func (cr ChainReaderImpl) CurrentHeader() *types.Header { panic("") }
func (cr ChainReaderImpl) GetHeader(hash libcommon.Hash, number uint64) *types.Header {
	if cr.blockReader != nil {
		h, _ := cr.blockReader.Header(context.Background(), cr.tx, hash, number)
		return h
	}
	return rawdb.ReadHeader(cr.tx, hash, number)
}
func (cr ChainReaderImpl) GetHeaderByNumber(number uint64) *types.Header {
	if cr.blockReader != nil {
		h, _ := cr.blockReader.HeaderByNumber(context.Background(), cr.tx, number)
		return h
	}
	return rawdb.ReadHeaderByNumber(cr.tx, number)

}
func (cr ChainReaderImpl) GetHeaderByHash(hash libcommon.Hash) *types.Header {
	if cr.blockReader != nil {
		number := rawdb.ReadHeaderNumber(cr.tx, hash)
		if number == nil {
			return nil
		}
		return cr.GetHeader(hash, *number)
	}
	h, _ := rawdb.ReadHeaderByHash(cr.tx, hash)
	return h
}
func (cr ChainReaderImpl) GetTd(hash libcommon.Hash, number uint64) *big.Int {
	td, err := rawdb.ReadTd(cr.tx, hash, number)
	if err != nil {
		log.Error("ReadTd failed", "err", err)
		return nil
	}
	return td
}

func setPalaConfig(commonConfigFile, hardforkConfigFile string, cfg *chain2.PalaConfig) {
	if hardforkConfigFile == "" || commonConfigFile == "" {
		return
	}

	var err error
	cfg.Hardforks = hardfork.NewHardforks(hardforkConfigFile)
	cfg.Common, err = ttConfig.New(commonConfigFile)
	if err != nil {
		panic(fmt.Sprintf("Failed to load thunder common config: %v", err))
	}
	committee.ThunderCoreGenesisCommInfo, err = committee.ReadGenesisCommInfo(cfg.Common.Key.GenesisCommPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load genesis committee info: %v", err))
	}
	committee.AlterCommInfo, err = committee.ReadAlterCommInfo(cfg.Common.Key.AlterCommPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load alter committee info: %v", err))
	}

	palaHardfork := hardfork.NewBoolHardforkConfig(
		"pala.hardfork",
		"The number of block we start run with pala protocol",
	)

	cfg.PalaBlock = big.NewInt(palaHardfork.GetEnabledBlockNum(cfg.Hardforks))

	verifyBid := hardfork.NewBoolHardforkConfig(
		"committee.verifyBid",
		"The session we begin to verify bids.",
	)

	cfg.VerifyBidSession = uint32(verifyBid.GetEnabledSessionNum(cfg.Hardforks))

	cfg.ElectionStopBlockSessionOffset = hardfork.NewInt64HardforkConfig(
		"election.stopBlockSessionOffset",
		"The Number of blocks that include transactions in one session.",
	)
	cfg.ProposerListName = hardfork.NewStringHardforkConfig(
		"committee.proposerList",
		"The name of proposer list we choose to use.",
	)
	cfg.MaxCodeSize = hardfork.NewInt64HardforkConfig(
		"protocol.maxCodeSize",
		"Maximum code size of a contract.",
	)
	cfg.GasTable = hardfork.NewStringHardforkConfig(
		"protocol.gasTable",
		"The gas table we choose to use.",
	)
	cfg.RewardScheme = hardfork.NewStringHardforkConfig(
		"committee.rewardScheme",
		"The scheme of reward dispatch hardfork",
	)
	cfg.VaultGasUnlimited = hardfork.NewBoolHardforkConfig(
		"committee.vaultGasUnlimited",
		"True if we don't limit the gas when vault calling other contract.",
	)
	cfg.EVMHardforkVersion = hardfork.NewStringHardforkConfig(
		"evm.version",
		"EVM hardfork version.",
	)
	cfg.IsConsensusInfoInHeader = hardfork.NewBoolHardforkConfig(
		"consensus.infoInHeader",
		"True if we store consensus info in Extra field of block header",
	)
	cfg.RNGVersion = hardfork.NewStringHardforkConfig(
		"trustedRNG.version",
		"RNG version",
	)
	cfg.BaseFee = hardfork.NewBigIntHardforkConfig(
		"protocol.baseFee",
		"protocol basefee",
	)
	cfg.TokenInflation = hardfork.NewBigIntHardforkConfig(
		"protocol.inflation",
		"protocol token inflation",
	)
	cfg.CommitteeRewardRatio = hardfork.NewInt64HardforkConfig(
		"committee.rewardRatio",
		"ratio of committee reward share",
	)
	cfg.TPCRevertDelegateCall = hardfork.NewBoolHardforkConfig(
		"precompiled.revertDelegateCall",
		"Revert deletegate call wehn calling precompiled contract",
	)
	cfg.K = hardfork.NewInt64HardforkConfig(
		"consensus.k",
		"Max unnotarized proposals",
	)

	precompile.Init()
}
