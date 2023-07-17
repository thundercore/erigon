package storage

import (
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/log/v3"
)

type epochStatus struct {
	epoch     blocksn.Epoch
	clockNota tt.ClockMsgNota
}

type EpochCache struct {
	mu         ttCommon.CheckedLock
	marshaller tt.DataUnmarshaller
	cached     *epochStatus
}

func NewEpochCache(tx kv.RwTx, marshaller tt.DataUnmarshaller) *EpochCache {
	return &EpochCache{
		marshaller: marshaller,
		cached:     updateEpochStatusIfNotExisted(tx, marshaller),
	}
}

func updateEpochStatusIfNotExisted(tx kv.RwTx, marshaller tt.DataUnmarshaller) *epochStatus {
	if es := readEpochStatus(tx, marshaller); es != nil {
		return es
	}
	es := &epochStatus{epoch: blocksn.Epoch{Session: 1, E: 1}}
	if err := writeEpochStatus(tx, es); err != nil {
		return nil
	}
	return es
}

func (em *EpochCache) GetEpoch() blocksn.Epoch {
	em.mu.Lock()
	defer em.mu.Unlock()

	return em.cached.epoch
}

func (em *EpochCache) UpdateByReconfiguration(tx kv.RwTx, s blocksn.Session) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	if em.cached != nil && em.cached.epoch.Session > s {
		debug.Bug("Update session backward %d->%d is forbidden.", em.cached.epoch.Session, s)
	}

	es := &epochStatus{
		epoch:     blocksn.NewEpoch(uint32(s), 1),
		clockNota: nil,
	}
	log.Info("Epoch progress", "from", em.cached.epoch, "to", es.epoch)

	if err := writeEpochStatus(tx, es); err != nil {
		return err
	}

	em.cached = es
	return nil
}

func (em *EpochCache) UpdateByClockMsgNota(tx kv.RwTx, cn tt.ClockMsgNota) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	if em.cached != nil && em.cached.epoch.Compare(cn.GetEpoch()) > 0 {
		debug.Bug("Update epoch backward %s->%s is forbidden.", em.cached.epoch, cn.GetEpoch())
	}
	if cnImpl, ok := cn.(*clockMsgNotaImpl); ok {
		status := cnImpl.getStatus()
		if status != valid {
			debug.Bug("clockMsgNota (%s) is not valid (%d)", cn.GetBlockSn(), status)
		}
	}

	log.Debug("Epoch progress", "from", em.cached.epoch, "to", cn.GetEpoch())

	es := &epochStatus{
		epoch:     cn.GetEpoch(),
		clockNota: cn,
	}

	if err := writeEpochStatus(tx, es); err != nil {
		return err
	}

	if err := WriteClockMsgNotarization(tx, cn); err != nil {
		return err
	}

	em.cached = es

	return nil
}

// TODO(frog): this may not get the last ClockMsgNota.
func (em *EpochCache) GetLatestClockMsgNota(tx kv.Tx, session blocksn.Session) tt.ClockMsgNota {
	em.mu.Lock()
	defer em.mu.Unlock()

	// case 0: hit cache
	if session == em.cached.epoch.Session {
		return em.cached.clockNota
	}

	// case 1: stop block exists, linear search to get last session.
	header, sn := readSessionStopHeader(tx, uint32(session))
	if header == nil {
		log.Error("NoStopBlock session", "at", session)
		return nil
	}

	epoch := sn.Epoch
	for num := header.Number.Uint64() + 1; ; num++ {
		h, err := rawdb.ReadCanonicalHash(tx, num)
		if err != nil {
			log.Error("Failed to read canonical hash", "num", num)
			return nil
		}
		if h == (common.Hash{}) {
			break
		}

		header := rawdb.ReadHeader(tx, h, num)
		if header == nil {
			debug.Bug("missing header (%q %d)", h, num)
		}

		_, sn, err := blocksn.DecodeBlockSnFromNumber(header.Difficulty)
		if err != nil {
			debug.Bug("Cannot decode block sn from block header of (%q %d)", h, num)
		}

		if sn.Epoch.Session > session {
			break
		}

		epoch = sn.Epoch
	}

	return ReadClockMsgNotarization(tx, em.marshaller, epoch)
}
