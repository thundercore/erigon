package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
	datadir2 "github.com/ledgerwatch/erigon-lib/common/datadir"
	"github.com/ledgerwatch/erigon-lib/kv"
	kv2 "github.com/ledgerwatch/erigon-lib/kv/mdbx"
	"github.com/ledgerwatch/log/v3"
	"github.com/spf13/cobra"

	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/consensus/ethash"
	"github.com/ledgerwatch/erigon/consensus/pala"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/eth/ethconfig"
	"github.com/ledgerwatch/erigon/eth/stagedsync"
	"github.com/ledgerwatch/erigon/turbo/snapshotsync"
	"github.com/ledgerwatch/erigon/turbo/trie"
)

func init() {
	withBlock(stateRootFromCmd)
	withFrom(stateRootFromCmd)
	withDataDir(stateRootFromCmd)
	withChain(stateRootFromCmd)
	withHardfork(stateRootFromCmd)
	withCommonConfig(stateRootFromCmd)
	rootCmd.AddCommand(stateRootFromCmd)
}

var stateRootFromCmd = &cobra.Command{
	Use:   "stateroot2",
	Short: "Exerimental command to re-execute blocks from block and compute state root",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := log.New()
		return StateRootFrom(genesis, logger, fromBlock, block, datadirCli)
	},
}

func StateRootFrom(genesis *core.Genesis, logger log.Logger, fromBlock, toBlock uint64, datadir string) error {
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
		setPalaConfig(commonConfigFile, hardforkConfigFile, chainConfig.Pala)
		engine = pala.New(chainConfig)
	}

	noOpWriter := state.NewNoopWriter()
	interrupt := false
	block := fromBlock
	var tx kv.Tx
	defer func() {
		if tx != nil {
			tx.Rollback()
		}
	}()

	for !interrupt {
		block++
		if block >= toBlock {
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
		var rwTx kv.RwTx
		if rwTx, err = db.BeginRw(ctx); err != nil {
			return err
		}
		defer rwTx.Rollback()

		w := state.NewPlainStateWriter(rwTx, nil, block)
		r := state.NewPlainState(historyTx, block, make(map[libcommon.Address][]libcommon.CodeRecord))
		intraBlockState := state.New(r)
		getHeader := func(hash libcommon.Hash, number uint64) *types.Header {
			return rawdb.ReadHeader(historyTx, hash, number)
		}

		stateRootFn := func() (*libcommon.Hash, error) {
			return stagedsync.CalculateStateRoot(rwTx)
		}

		headerReader := ChainReaderImpl{config: chainConfig, tx: tx, blockReader: blockReader}

		if _, err = runBlock(engine, intraBlockState, noOpWriter, w, chainConfig, getHeader, b, vmConfig, false, headerReader, stateRootFn); err != nil {
			return fmt.Errorf("block %d: %w", block, err)
		}
		if block+1 == toBlock {
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
	fmt.Printf("StateRoot calculated from %d to %d\n", fromBlock+1, toBlock)
	return nil
}
