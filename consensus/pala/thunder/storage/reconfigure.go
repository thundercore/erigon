package storage

import (
	"fmt"

	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
	tt "github.com/ledgerwatch/erigon/consensus/pala/thunder/types"
)

const numOfPreservedERs = 2

func getNextSession(tx kv.Tx, config *chain.PalaConfig) blocksn.Session {
	sn, err := ReadFinalizedBlockSn(tx)
	if err != nil {
		logger.Error("Failed to read finalized blockSn", "err", err)
		return 0
	}
	blk := ReadBlockFromBlockSn(tx, sn, config)
	if blk == nil {
		logger.Crit("Failed to read block from blocksn", "sn", sn.String())
	}

	return blk.GetBlockSn().Epoch.Session + 1
}

func getNextElectionResult(tx kv.Tx, config *chain.PalaConfig) (*ElectionResultImpl, error) {
	s := getNextSession(tx, config)
	commInfo := GetBlockCommitteeBySession(uint32(s), config, tx)
	if commInfo == nil {
		return nil, fmt.Errorf("failed to get committee info for session %d", s)
	}
	return NewElectionResultImpl(commInfo, s), nil
}

func UpdateVerifier(tx kv.RwTx, config *chain.PalaConfig, verifier tt.Verifier) error {
	er, err := getNextElectionResult(tx, config)
	if err != nil {
		return err
	}

	v := verifier.(*VerifierImpl)
	v.AddElectionResult(er)
	if er.GetSession() > numOfPreservedERs {
		v.CleanupElectionResult(er.GetSession() - numOfPreservedERs)
	}
	return nil
}

func UpdateEpochCache(c *EpochCache, tx kv.RwTx, config *chain.PalaConfig) error {
	s := getNextSession(tx, config)
	return c.UpdateByReconfiguration(tx, s)
}
