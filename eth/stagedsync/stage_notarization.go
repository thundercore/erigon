package stagedsync

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/dbg"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/bls"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/storage"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/eth/stagedsync/stages"
	"github.com/ledgerwatch/erigon/turbo/services"
	"github.com/ledgerwatch/log/v3"
)

type NotarizationCfg struct {
	db                   kv.RwDB
	chainConfig          chain.Config
	blockReader          services.FullBlockReader
	verifier             tt.Verifier
	reconfiguringSession *blocksn.Session
	epoch                blocksn.Epoch
}

func (cfg *NotarizationCfg) SetEpoch(epoch blocksn.Epoch) error {
	if epoch.Compare(cfg.epoch) <= 0 {
		log.Warn("Skip update epoch", "epoch", epoch.String(), "current", cfg.epoch.String())
		return fmt.Errorf("skip update epoch")
	}

	cfg.epoch = epoch
	return nil
}

func makeBlockGetterFunc(reader services.FullBlockReader) storage.BlockGetFunc {
	return func(tx kv.Tx, hash libcommon.Hash, num uint64) *types.Block {
		blk, _, err := reader.BlockWithSenders(context.Background(), tx, hash, num)
		if err != nil {
			return nil
		}
		return blk
	}
}

func newVerifier(db kv.RoDB, palaConfig *chain.PalaConfig, blockReader services.FullBlockReader) tt.Verifier {
	if palaConfig == nil {
		return nil
	}

	tx, err := db.BeginRo(context.Background())
	if err != nil {
		log.Error("Failed to begin tx", "err", err)
		return nil
	}
	defer tx.Rollback()

	sn, err := storage.ReadFreshestNotarizedHeadSn(tx)
	if err != nil {
		log.Error("Failed to read freshest notarized head", "err", err)
		return nil
	}

	blk := storage.ReadBlockFromBlockSnWithBlockGetter(tx, sn, palaConfig, makeBlockGetterFunc(blockReader))
	header := rawdb.ReadHeader(tx, libcommon.BytesToHash(blk.GetHash().Bytes()), blk.GetNumber())

	reader := state.NewPlainState(tx, header.Number.Uint64(), make(map[libcommon.Address][]libcommon.CodeRecord))
	ibs := state.New(reader)

	commInfo := storage.GetBlockCommittee(header, ibs, palaConfig)
	if commInfo == nil {
		log.Error("Failed to get committee info", "number", header.Number.String(), "sn", sn.String())
		return nil
	}
	if sn.Epoch.Session < 1 {
		sn.Epoch.Session = 1
	}
	electionResults := storage.NewElectionResultImpl(commInfo, sn.Epoch.Session)

	signer, err := bls.NewSigningKey()
	if err != nil {
		log.Error("Failed to create new signing key", "err", err)
		return nil
	}

	verifier := storage.NewVerifierImpl(&storage.VerifierImplCfg{Config: palaConfig, Signer: signer, ElectionResult: electionResults})

	return verifier
}

func shouldReconfigure(tx kv.RwTx, cfg NotarizationCfg) bool {
	sb := storage.GetLatestFinalizedStopBlock(tx, cfg.chainConfig.Pala, makeBlockGetterFunc(cfg.blockReader))
	if sb == nil {
		return false
	}

	sbSession := sb.GetBlockSn().Epoch.Session
	fhSn, err := storage.ReadFinalizedBlockSn(tx)
	if err != nil {
		log.Error("Failed to read finalized block sn", "err", err)
		return false
	}
	return sbSession > 0 && sbSession == fhSn.Epoch.Session
}

func reconfigure(tx kv.RwTx, cfg NotarizationCfg, ec *storage.EpochCache, finalized blocksn.BlockSn) error {
	if err := storage.UpdateVerifier(tx, cfg.chainConfig.Pala, cfg.verifier); err != nil {
		log.Error("Failed to update verifier", "err", err)
		return err
	}

	cfg.reconfiguringSession = &finalized.Epoch.Session

	oldEpoch := ec.GetEpoch()
	if oldEpoch.Session >= *cfg.reconfiguringSession+1 {
		return nil
	}

	err := storage.UpdateEpochCache(ec, tx, cfg.chainConfig.Pala)
	if err != nil {
		return err
	}

	cfg.SetEpoch(ec.GetEpoch())

	return nil
}

func setEpoch(cNota tt.ClockMsgNota, cfg NotarizationCfg, ec *storage.EpochCache, tx kv.RwTx) error {
	oldEpoch := ec.GetEpoch()
	if oldEpoch.Compare(cNota.GetEpoch()) > 0 {
		return nil
	}

	if err := ec.UpdateByClockMsgNota(tx, cNota); err != nil {
		return err
	}
	newEpoch := ec.GetEpoch()
	if oldEpoch.Compare(newEpoch) == 0 {
		return nil
	}

	return cfg.SetEpoch(newEpoch)
}

func StageNotaCfg(db kv.RwDB, chainConfig chain.Config, blockReader services.FullBlockReader) NotarizationCfg {
	return NotarizationCfg{
		db:          db,
		chainConfig: chainConfig,
		blockReader: blockReader,
		verifier:    newVerifier(db, chainConfig.Pala, blockReader),
		epoch:       blocksn.Epoch{},
	}
}

func NotaForward(
	s *StageState,
	u Unwinder,
	ctx context.Context,
	tx kv.RwTx,
	cfg NotarizationCfg,
	test bool,
	firstCycle bool,
	quiet bool,
) error {
	if cfg.verifier == nil {
		log.Info("Pala is not enabled, skipping notarization stage")
		return nil
	}

	var err error
	useExternalTx := tx != nil
	if !useExternalTx {
		tx, err = cfg.db.BeginRw(context.Background())
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}

	epochCache := storage.NewEpochCache(tx, storage.NewDataUnmarshaller(cfg.chainConfig.Pala))
	cfg.SetEpoch(epochCache.GetEpoch())

	var bodyProgress, notaProgress uint64
	bodyProgress, err = stages.GetStageProgress(tx, stages.Bodies)
	if err != nil {
		return err
	}

	notaProgress = s.BlockNumber
	if notaProgress >= bodyProgress {
		return nil
	}

	logPrefix := s.LogPrefix()
	log.Info(fmt.Sprintf("[%s] Processing notas...", logPrefix), "from", notaProgress, "to", bodyProgress)

	logEvery := time.NewTicker(logInterval)
	defer logEvery.Stop()

	var (
		stopped = false
	)

	fsn, err := storage.ReadFinalizedBlockSn(tx)
	if err != nil {
		return err
	}
	if shouldReconfigure(tx, cfg) {
		err = reconfigure(tx, cfg, epochCache, fsn)
		if err != nil {
			return err
		}
	}

	skipFirst := notaProgress != 0
	for nextBlock := notaProgress; nextBlock <= bodyProgress; nextBlock++ {
		// skip first cycle because we already processed it for non 0 block
		if skipFirst {
			skipFirst = false
			continue
		}

		if !quiet {
			select {
			case <-logEvery.C:
				logWritingNotas(logPrefix, notaProgress, bodyProgress)
			default:
			}
		}

		b := storage.GetBlockByNumber(tx, nextBlock, cfg.chainConfig.Pala)

		unmarshaller := storage.NewDataUnmarshaller(cfg.chainConfig.Pala)
		decoder := storage.NewBlockImplDecoder(unmarshaller)

		notas := decoder.GetNotarizations(b, cfg.chainConfig.Pala)
		cNota := decoder.GetClockMsgNota(b, cfg.chainConfig.Pala)

		if cNota != nil {
			if err := cfg.verifier.VerifyClockMsgNota(cNota); err != nil {
				return err
			}

			if cNota.GetEpoch().Compare(cfg.epoch) > 0 {
				err = setEpoch(cNota, cfg, epochCache, tx)
				if err != nil {
					return err
				}
			}
		}

		for _, nota := range notas {
			existedNota := storage.ReadNotarization(tx, nota.GetBlockSn(), cfg.chainConfig.Pala)
			if existedNota != nil && existedNota.GetNVote() >= nota.GetNVote() {
				continue
			}

			cr := storage.NewChainReader(tx, cfg.chainConfig.Pala)
			if err := cfg.verifier.VerifyNotarization(nota, cr); err != nil {
				return err
			}

			if _, _, err := storage.AddNotarization(tx, nota, cfg.chainConfig.Pala); err != nil {
				return err
			}
		}

		if nextBlock > notaProgress {
			notaProgress = nextBlock
			if err = s.Update(tx, nextBlock); err != nil {
				return fmt.Errorf("saving nota progress: %w", err)
			}
		}

		if shouldReconfigure(tx, cfg) {
			err = reconfigure(tx, cfg, epochCache, b.GetBlockSn())
			if err != nil {
				return err
			}
		}

		select {
		case <-ctx.Done():
			stopped = true
		default:
		}
	}

	if !useExternalTx {
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	if stopped {
		return libcommon.ErrStopped
	}
	if notaProgress > s.BlockNumber+16 {
		log.Info(fmt.Sprintf("[%s] Processed", logPrefix), "highest", notaProgress)
	}

	return nil
}

func UnwindNotaStage(u *UnwindState, tx kv.RwTx, cfg NotarizationCfg, ctx context.Context) error {
	return nil
}

func PruneNotaStage(s *PruneState, tx kv.RwTx, cfg NotarizationCfg, ctx context.Context) (err error) {
	return nil
}

func logWritingNotas(logPrefix string, committed, headerProgress uint64) {
	var m runtime.MemStats
	dbg.ReadMemStats(&m)
	remaining := headerProgress - committed
	log.Info(fmt.Sprintf("[%s] Writing block notas", logPrefix),
		"block_num", committed,
		"remaining", remaining,
		"alloc", libcommon.ByteCount(m.Alloc),
		"sys", libcommon.ByteCount(m.Sys),
	)
}
