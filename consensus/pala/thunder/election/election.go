package election

import (
	"encoding/hex"
	"math/big"
	"sort"

	"github.com/ledgerwatch/erigon-lib/thunder/hardfork"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/committee"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	"github.com/ledgerwatch/erigon/rlp"
	"github.com/ledgerwatch/log/v3"
)

var (
	logger           = log.New("package", "thunder/election")
	minCommitteeSize = hardfork.NewInt64HardforkConfig(
		"committee.minCommitteeSize",
		"min number of committee members to form a committee")

	// These are the original values
	// auctionStakeThresholdAmount, _ = big.NewInt(0).SetString("500000000000000000000000", 10) // 500000 thunder
	// minBidderStakeAmount, _        = big.NewInt(0).SetString("100000000000000000000000", 10) // 100000 thunder
	// minGasBidPrice, _              = big.NewInt(0).SetString("10000000", 10)                 // 0.01 gella

	// exposed for thundervm unit tests
	AuctionStakeThreshold = hardfork.NewBigIntHardforkConfig(
		"committee.AuctionStakeThreshold",
		"min number of Thunder tokens required to form a committee")
	MinBidderStake = hardfork.NewBigIntHardforkConfig(
		"committee.MinBidderStake",
		"min number of Thunder tokens required for a bidder")
	MinBidPrice = hardfork.NewBigIntHardforkConfig(
		"committee.MinGasBidPrice",
		"minimum gas bid price")

	// hardfork flags
	BurnReward = hardfork.NewBoolHardforkConfig(
		"vault.burnReward",
		"committee rewards are burned if sent to address 0")
	ElectionScheme = hardfork.NewStringHardforkConfig(
		"committee.electionScheme",
		"the committee election scheme in use")
	expectedCommSize = hardfork.NewInt64HardforkConfig(
		"committee.expectedCommSize",
		"the expected commSize (the K value of the Top-K scheme), should be larger than minCommitteeSize")
)

// Result holds the outcome of a committee election.
type Result struct {
	Members          []committee.MemberInfo
	ClearingGasPrice *big.Int
}

// ToBytes serializes an election.Result to bytes (uses the RLP trans-coding interfaces)
func (r *Result) ToBytes() []byte {
	buf, err := rlp.EncodeToBytes(r)
	if err != nil {
		debug.Bug("ToBytes error: %s", err)
	}
	return buf
}

// From bytes decodes an RLP encoded buffer into a fully formed election.Result struct.
func (r *Result) FromBytes(buf []byte) error {
	return rlp.DecodeBytes(buf, r)
}

// Elect returns the result of a committee election given stake-in messages.
// The stakes are ordered from old to new which is used as a tiebreaker in the election.
// It is important to the election result to be determinitic so all nodes have the consistent
// election result.
func Elect(hk *hardfork.Hardforks, stakes []*StakeInfo, freeze func(*StakeInfo) bool, sessionNum int64) *Result {
	logger.Info("Elect", "len(stakes)", len(stakes))

	candidates := getCandidates(hk, stakes, sessionNum)
	return elect(hk, candidates, freeze, sessionNum)
}

func ElectR3(hk *hardfork.Hardforks, stakes []*StakeInfo, freeze func(*StakeInfo) bool, sessionNum int64) *Result {
	logger.Info("ElectR3", "len(stakes)", len(stakes))

	candidates := getCandidatesR3(hk, stakes, sessionNum)
	return elect(hk, candidates, freeze, sessionNum)
}

// getCandidates filters out invalid stakes and returns a list of candidates ordered by
// Stake / GasPrice. The original order of stakes is used as a tiebreaker.
func getCandidates(hk *hardfork.Hardforks, stakes []*StakeInfo, sessionNum int64) []*StakeInfo {
	candidates := []*StakeInfo{}
	// Since new stake message overwrites old ones, process in reverse order. For each
	// PubVoteKey & StakingAddr, only the last stake message is valid.
	seen := make(map[string]bool)
	for i := len(stakes) - 1; i >= 0; i-- {
		s := stakes[i]
		if s.GasPrice.Sign() <= 0 {
			logger.Warn("Invalid gas price (<= 0)", "from", s.StakingAddr)
			// we don't allow negative or 0 gasprice
			continue
		}
		in := append(s.PubVoteKey.ToBytes(), s.StakingAddr.Bytes()...)
		in = append(in, s.RefundID...)
		k := string(in)
		_, found := seen[k]
		if found {
			// Filter out old StakeInfo with same PubVoteKey & StakingAddr
			logger.Warn("Dup candidate",
				"vote key",
				hex.EncodeToString(s.PubVoteKey.ToBytes()),
				"staking address",
				s.StakingAddr.Hex(),
				"refundId",
				hex.EncodeToString(s.RefundID))
			continue
		}
		seen[k] = true
		if s.Stake.Cmp(MinBidderStake.GetValueHardforkAtSession(hk, sessionNum)) == -1 {
			// Filter out StakeInfo with less than min bidder stake
			logger.Warn("Stake too small", "amount", s.Stake, "from", s.StakingAddr, "min",
				MinBidderStake.GetValueHardforkAtSession(hk, sessionNum))
			continue
		}
		candidates = append(candidates, s)
	}

	// Sort candidates by Stake / GasPrice in decreasing order.
	// Since candidates are appended above in reversed order, reverse back to original order
	// to use as a tiebreaker. It is important that all nodes generate the same election.result.
	for i, j := 0, len(candidates)-1; i < j; i, j = i+1, j-1 {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}

	// To avoid division by zero, use equivalent condition:
	// stake[i] / price[i] < stake[j] / price[j] <=> stake[i] * price[j] < stake[j] * price[i]
	sort.SliceStable(candidates, func(i int, j int) bool {
		return big.NewInt(0).Mul(candidates[j].Stake, candidates[i].GasPrice).Cmp(
			big.NewInt(0).Mul(candidates[i].Stake, candidates[j].GasPrice)) == -1

	})

	return candidates
}

// getCandidates filters out invalid stakes and returns a list of candidates ordered by
// Stake. The original order of stakes is used as a tiebreaker.
func getCandidatesR3(hk *hardfork.Hardforks, stakes []*StakeInfo, sessionNum int64) []*StakeInfo {
	candidates := []*StakeInfo{}
	// Since new stake message overwrites old ones, process in reverse order. For each
	// PubVoteKey & StakingAddr, only the last stake message is valid.
	seen := make(map[string]bool)
	for i := len(stakes) - 1; i >= 0; i-- {
		s := stakes[i]
		if s.GasPrice.Sign() <= 0 {
			logger.Warn("Invalid gas price (<= 0)", "from", s.StakingAddr)
			// we don't allow negative or 0 gasprice
			continue
		}
		in := append(s.PubVoteKey.ToBytes(), s.StakingAddr.Bytes()...)
		in = append(in, s.RefundID...)
		k := string(in)
		_, found := seen[k]
		if found {
			// Filter out old StakeInfo with same PubVoteKey & StakingAddr
			logger.Warn("Dup candidate",
				"vote key",
				hex.EncodeToString(s.PubVoteKey.ToBytes()),
				"staking address",
				s.StakingAddr.Hex(),
				"refundId",
				hex.EncodeToString(s.RefundID))
			continue
		}
		seen[k] = true
		if s.Stake.Cmp(MinBidderStake.GetValueHardforkAtSession(hk, sessionNum)) == -1 {
			// Filter out StakeInfo with less than min bidder stake
			logger.Warn("Stake too small", "amount", s.Stake, "from", s.StakingAddr, "min",
				MinBidderStake.GetValueHardforkAtSession(hk, sessionNum))
			continue
		}
		candidates = append(candidates, s)
	}

	// Sort candidates by Stake in decreasing order.
	// Since candidates are appended above in reversed order, reverse back to original order
	// to use as a tiebreaker. It is important that all nodes generate the same election.result.
	for i, j := 0, len(candidates)-1; i < j; i, j = i+1, j-1 {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}

	// sort candidates by staked amount
	sort.SliceStable(candidates, func(i int, j int) bool {
		return candidates[i].Stake.Cmp(candidates[j].Stake) == 1
	})

	return candidates
}

func logStakeInfos(logger log.Logger, candidates []*StakeInfo) {
	for i, c := range candidates {
		logger.Info("StakeInfos",
			"index", i,
			"PubVoteKey", hex.EncodeToString(c.PubVoteKey.ToBytes())[:16],
			"Coinbase", c.Coinbase.Hex()[:16],
			"Stake", ttCommon.WeiToEther(c.Stake).String(),
			"GasPrice", c.GasPrice.String())
	}
}

func logMemberInfos(logger log.Logger, members []committee.MemberInfo) {
	for i, m := range members {
		logger.Info("MemberInfos",
			"index", i,
			"PubVoteKey", hex.EncodeToString(m.PubVoteKey.ToBytes())[:16],
			"Coinbase", m.Coinbase.Hex()[:16],
			"Stake", ttCommon.WeiToEther(m.Stake).String(),
			"GasPrice", m.GasPrice.String())
	}
}

// elect returns the election result given a valid and sorted list of candidates. If the list of
// candidates is not able to form a committee, elect returns nil.
func elect(hk *hardfork.Hardforks, candidates []*StakeInfo, freeze func(*StakeInfo) bool, sessionNum int64) *Result {
	result := &Result{
		Members:          []committee.MemberInfo{},
		ClearingGasPrice: big.NewInt(0),
	}
	logger.Info("elect", "len(candidates)", len(candidates), "session", sessionNum)
	logStakeInfos(logger, candidates)

	// Keep track of stake in the current auction
	auctionStake := big.NewInt(0)
	// Since PubVoteKey should be unique in a committee, we track seen PubVoteKeys to filter out
	// candidates with the same PubVoteKey as a previous committee member. Candidates are already
	// sorted by stake so taking the first occurrence of the PubVoteKey is akin to taking the
	// largest one with the greatest bid.
	seen := make(map[string]bool)
	for _, c := range candidates {
		k := string(c.PubVoteKey.ToBytes())
		_, found := seen[k]
		if found {
			// consider changing criterion for picking candidates with dup PubVoteKeys, see THUNDER-519
			logger.Warn("Dup vote key", "key", k)
			continue
		}
		seen[k] = true

		if !freeze(c) {
			logger.Warn("Freeze failed", "from", c.StakingAddr)
			continue
		}

		// Add the current candidate to election.result
		result.Members = append(result.Members, *c.ToMemberInfo())
		// Set the ClearingGasPrice to the maximum bid
		if result.ClearingGasPrice.Cmp(c.GasPrice) == -1 {
			result.ClearingGasPrice.Set(c.GasPrice)
		}

		switch ElectionScheme.GetValueHardforkAtSession(hk, sessionNum) {
		case "TotalStakeThreshold":
			// Return election result when min auction stake is reached.
			auctionStake = auctionStake.Add(auctionStake, c.Stake)
			if auctionStake.Cmp(AuctionStakeThreshold.GetValueHardforkAtSession(hk, sessionNum)) >= 0 &&
				int64(len(result.Members)) >= minCommitteeSize.GetValueHardforkAtSession(hk, sessionNum) {

				logger.Info("TotalStakeThreshold", "committee",
					len(result.Members), "clearingGasPrice", result.ClearingGasPrice.Int64())
				logMemberInfos(logger, result.Members)

				return result
			}
		case "TopKCandidates":
			if int64(len(result.Members)) == expectedCommSize.GetValueHardforkAtSession(hk, sessionNum) {
				logger.Info("TopKCandidates", "committee",
					len(result.Members), "clearingGasPrice", result.ClearingGasPrice.Int64())
				logMemberInfos(logger, result.Members)

				return result
			}
		}

		if int64(len(result.Members)) >= committee.MaxCommSize {
			// The committee size should not be more than max commitee size.
			logger.Warn("Exceed max comm size", "committee",
				len(result.Members), "limit", committee.MaxCommSize)
			break
		}
	}

	if ElectionScheme.GetValueHardforkAtSession(hk, sessionNum) == "TopKCandidates" &&
		int64(len(result.Members)) >= minCommitteeSize.GetValueHardforkAtSession(hk, sessionNum) {
		logger.Info("Eelct", "committee",
			len(result.Members), "clearingGasPrice", result.ClearingGasPrice.Int64())
		logMemberInfos(logger, result.Members)

		return result
	}

	logger.Warn("Elect failed", "total_stake", auctionStake, "members", len(result.Members))
	return nil
}
