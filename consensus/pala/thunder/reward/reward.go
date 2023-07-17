package reward

import (
	// Standard imports
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/committee"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/log/v3"
)

const (
	totalFeeStr     = "totalFee"
	accelFeeStr     = "accelFee"
	committeeFeeStr = "committeeFee"
	recordStr       = "Record"

	inflationKey = "thunderTotalInflation"
	feeBurnedKey = "thunderFeeBurned"
)

type feeHashRecord struct {
	total, accel, committee common.Hash
}

var (
	logger  = log.New("package", "thunder/reward")
	feeHash = feeHashRecord{
		total:     common.Hash(sha256.Sum256([]byte(totalFeeStr))),
		accel:     common.Hash(sha256.Sum256([]byte(accelFeeStr))),
		committee: common.Hash(sha256.Sum256([]byte(committeeFeeStr))),
	}

	feeRecord = feeHashRecord{
		total:     common.Hash(sha256.Sum256([]byte(totalFeeStr + recordStr))),
		accel:     common.Hash(sha256.Sum256([]byte(accelFeeStr + recordStr))),
		committee: common.Hash(sha256.Sum256([]byte(committeeFeeStr + recordStr))),
	}

	errInsufficientFeeBalance = fmt.Errorf("insufficient fee balance")

	totalInflationKeyHash = common.Hash(sha256.Sum256([]byte(inflationKey)))
	feeBurnedKeyHash      = common.Hash(sha256.Sum256([]byte(feeBurnedKey)))
)

// UpdateFees updates totalFee, accelFee and committeeFee based on committee clearingGasPrice
// accelGasPriceLimit for a block. The fees are cummulative over blocks within a committee interval.
func UpdateFees(state *state.IntraBlockState, txs types.Transactions, receipts []*types.Receipt,
	clearingGasPrice *big.Int, accelGasPriceLimit *big.Int) {
	if len(txs) != len(receipts) {
		debug.Fatal("transaction and receipt count mismatch")

	}

	totalFee := getFee(state, feeHash.total)
	accelFee := getFee(state, feeHash.accel)
	committeeFee := getFee(state, feeHash.committee)

	for i, tx := range txs {
		gasPrice := tx.GetPrice().ToBig()
		totalFee = totalFee.Add(totalFee, transactionFee(
			gasPrice, big.NewInt(int64(receipts[i].GasUsed))))

		if gasPrice.Cmp(clearingGasPrice) == -1 {
			if i == len(txs)-1 && gasPrice.Cmp(common.Big0) == 0 {
				// This is our consensus transactions
			} else {
				logger.Warn("transaction gasPrice is less than clearingGasPrice",
					"gasPrice", gasPrice, "clearingGasPrice", clearingGasPrice)
			}
		}

		commGasPrice := gasPriceMin(gasPrice, clearingGasPrice)
		committeeFee = committeeFee.Add(committeeFee, transactionFee(
			commGasPrice, big.NewInt(int64(receipts[i].GasUsed))))

		accelGasPrice := gasPriceMin(gasPrice.Sub(gasPrice, commGasPrice), accelGasPriceLimit)

		accelFee = accelFee.Add(accelFee, transactionFee(
			accelGasPrice, big.NewInt(int64(receipts[i].GasUsed))))

	}
	setFee(state, feeHash.total, totalFee)
	setFee(state, feeHash.accel, accelFee)
	setFee(state, feeHash.committee, committeeFee)
}

// Distribute sends transaction fees to accelerator, committee members and Thunder Foundation.
func Distribute(commInfo *committee.CommInfo, state *state.IntraBlockState) *Results {
	if len(commInfo.MemberInfo) == 0 {
		// If there are zero committee members, info, not fatal
		logger.Info("empty committees")
		// process as normal
	}
	results, err := getCurrentDistribution(commInfo, state)
	if err != nil {
		logger.Error("getResults error", "err", err)
		return nil
	}
	err = distribute(state, results)
	if err != nil {
		logger.Error("distribute error", "err", err)
		return nil
	}
	return results
}

// Distribute sends transaction fees to accelerator, committee members and Thunder Foundation.
func DistributeR4(commInfo *committee.CommInfo, state *state.IntraBlockState) *Results {
	if len(commInfo.MemberInfo) == 0 {
		// If there are zero committee members, info, not fatal
		logger.Info("empty committees")
		// process as normal
	}
	results, err := getCurrentDistribution(commInfo, state)
	if err != nil {
		logger.Error("getResults error", "err", err)
		return nil
	}
	err = distributeR4(state, results)
	if err != nil {
		logger.Error("distribute error", "err", err)
		return nil
	}
	return results
}

// UpdateFeesR2P5 if a new way to dispatch gas, divided fee to two equal parts,
// for proposers and for voters.
func UpdateFeesR2P5(state *state.IntraBlockState, txs types.Transactions, receipts []*types.Receipt) {
	if len(txs) != len(receipts) {
		debug.Fatal("transaction and receipt count mismatch")
	}

	totalFee := getFee(state, feeHash.total)
	accelFee := getFee(state, feeHash.accel)
	committeeFee := getFee(state, feeHash.committee)

	for i, tx := range txs {
		gasPrice := tx.GetPrice().ToBig()
		fee := transactionFee(gasPrice, big.NewInt(int64(receipts[i].GasUsed)))
		totalFee = totalFee.Add(totalFee, fee)

		halfFee := new(big.Int).Quo(fee, common.Big2)
		committeeFee = committeeFee.Add(committeeFee, halfFee)

		remainingFee := new(big.Int).Sub(fee, halfFee)
		accelFee = accelFee.Add(accelFee, remainingFee)
	}
	setFee(state, feeHash.total, totalFee)
	setFee(state, feeHash.accel, accelFee)
	setFee(state, feeHash.committee, committeeFee)
}

// UpdateFeesR4 if a new way to dispatch gas, divided fee to two equal parts,
// for proposers and for voters.
func UpdateFeesR4(state *state.IntraBlockState, txs types.Transactions, receipts []*types.Receipt,
	inflation, baseFee *big.Int, committeeRewardRatio int64) {
	if len(txs) != len(receipts) {
		debug.Fatal("transaction and receipt count mismatch")
	}

	ratioUpperbound := int64(100)
	if committeeRewardRatio > ratioUpperbound {
		debug.Fatal("wrong reward distribute ratio")
	}

	if baseFee == nil {
		baseFee = common.Big0
	}
	totalFee := getFee(state, feeHash.total)
	accelFee := getFee(state, feeHash.accel)
	committeeFee := getFee(state, feeHash.committee)

	accumulatedFee := new(big.Int).Set(inflation)
	burnedFee := big.NewInt(0)
	for i, tx := range txs {
		gasPrice := tx.GetPrice().ToBig()
		if gasPrice.Cmp(baseFee) <= 0 {
			logger.Warn("GasPrice less than baseFee",
				"txHash",
				tx.Hash().Hex(),
				"gasPrice",
				gasPrice.String(),
				"baseFee",
				baseFee.String())
			continue
		}
		gasPrice = new(big.Int).Sub(gasPrice, baseFee)
		fee := transactionFee(gasPrice, big.NewInt(int64(receipts[i].GasUsed)))
		accumulatedFee = accumulatedFee.Add(accumulatedFee, fee)
		burnedFee = burnedFee.Add(burnedFee,
			new(big.Int).Mul(baseFee, big.NewInt(int64(receipts[i].GasUsed))))
	}

	totalFee = totalFee.Add(totalFee, accumulatedFee)

	committeeShare := mulDiv(accumulatedFee, big.NewInt(committeeRewardRatio), big.NewInt(ratioUpperbound))
	committeeFee = committeeFee.Add(committeeFee, committeeShare)
	accelShare := new(big.Int).Sub(accumulatedFee, committeeShare)
	accelFee = accelFee.Add(accelFee, accelShare)

	setFee(state, feeHash.total, totalFee)
	setFee(state, feeHash.accel, accelFee)
	setFee(state, feeHash.committee, committeeFee)

	addInflation(state, inflation)
	addFeeBurned(state, burnedFee)
}

// gasPriceMin returns the min of 2 gas prices
func gasPriceMin(a *big.Int, b *big.Int) *big.Int {
	if a.Cmp(b) >= 0 {
		return b
	} else {
		return a
	}
}

// getFee returns fee stored at a given hash in state DB.
// When the key is missing, getFee returns zero.
func getFee(state *state.IntraBlockState, key common.Hash) *big.Int {
	value := &uint256.Int{}
	state.GetState(ttCommon.DefaultCoinbaseAddress, &key, value)
	return value.ToBig()
}

// setFee stores fee at a given hash in stateDB.
func setFee(state *state.IntraBlockState, key common.Hash, fee *big.Int) {
	value := uint256.Int{}
	value.SetFromBig(fee)
	state.SetState(ttCommon.DefaultCoinbaseAddress, &key, value)
}

func addInflation(state *state.IntraBlockState, inflation *big.Int) {
	totalInflation := GetTotalInflation(state)
	totalInflation = totalInflation.Add(totalInflation, inflation)
	value := uint256.Int{}
	value.SetFromBig(totalInflation)
	state.SetState(ttCommon.DefaultCoinbaseAddress, &totalInflationKeyHash, value)
}

func GetTotalInflation(state *state.IntraBlockState) *big.Int {
	value := &uint256.Int{}
	state.GetState(ttCommon.DefaultCoinbaseAddress, &totalInflationKeyHash, value)
	return value.ToBig()
}

func addFeeBurned(state *state.IntraBlockState, fee *big.Int) {
	feeBurned := GetTotalFeeBurned(state)
	newFeeBurned := new(big.Int).Add(feeBurned, fee)
	value := uint256.Int{}
	value.SetFromBig(newFeeBurned)
	state.SetState(ttCommon.DefaultCoinbaseAddress, &feeBurnedKeyHash, value)
}

func GetTotalFeeBurned(state *state.IntraBlockState) *big.Int {
	value := &uint256.Int{}
	state.GetState(ttCommon.DefaultCoinbaseAddress, &feeBurnedKeyHash, value)
	return value.ToBig()
}

func transactionFee(gasPrice *big.Int, gasUsed *big.Int) *big.Int {
	return new(big.Int).Mul(gasPrice, gasUsed)
}

// Payment contains the amounts to be given to a specific coinbase address.
type Payment struct {
	Coinbase common.Address
	Fee      *big.Int
}

// Results contains the fees to be distributed
type Results struct {
	Payments []Payment
}

// FromJSON decodes a JSON encoded buffer into a reward.Results struct.
func (r *Results) FromJSON(buf []byte) error {
	return json.Unmarshal(buf, r)
}

// ToJSON encodes a reward.Results struct to a JSON encoded buffer.
func (r *Results) ToJSON() []byte {
	buf, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		debug.Bug("Encoding of ToJSON failed error: %s", err)
	}
	return buf
}

func (pmt *Payment) Log(logger log.Logger) {
	logger.Info("[Payment]", "Coinbase", pmt.Coinbase.Hex(), "Fee", pmt.Fee.String())
}

func (rslts *Results) Log(logger log.Logger) {
	logger.Info("Results:")
	for _, nr := range rslts.Payments {
		nr.Log(logger)
	}
	logger.Info("---")
}

func (rslts *Results) AddValue(acct *common.Address, fees *big.Int) {
	rslts.Payments = append(rslts.Payments, Payment{
		Coinbase: *acct,
		Fee:      fees,
	})
}

func (rslts *Results) TotalFees() *big.Int {
	sum := big.NewInt(0)
	for _, nr := range rslts.Payments {
		sum.Add(sum, nr.Fee)
	}
	return sum
}

// distribute credits each coinbase of the current committee members according to
// the reward results and also debits from the fee coinbase address.
func distribute(state *state.IntraBlockState, results *Results) error {
	totalFees := new(uint256.Int)
	totalFees.SetFromBig(results.TotalFees())
	if state.GetBalance(ttCommon.DefaultCoinbaseAddress).Cmp(totalFees) == -1 {
		logger.Error("distribute error", "error", errInsufficientFeeBalance)
		return errInsufficientFeeBalance
	}
	for _, p := range results.Payments {
		fee := new(uint256.Int)
		fee.SetFromBig(p.Fee)
		state.AddBalance(p.Coinbase, fee)
	}
	state.SubBalance(ttCommon.DefaultCoinbaseAddress, totalFees)
	tFee := getFee(state, feeHash.total)
	aFee := getFee(state, feeHash.accel)
	cFee := getFee(state, feeHash.committee)

	setFee(state, feeHash.total, big.NewInt(0))
	setFee(state, feeHash.accel, big.NewInt(0))
	setFee(state, feeHash.committee, big.NewInt(0))

	setFee(state, feeRecord.total, tFee)
	setFee(state, feeRecord.accel, aFee)
	setFee(state, feeRecord.committee, cFee)
	return nil
}

// distributeR4 credits each coinbase of the current committee members according to
// the reward results in the air.
func distributeR4(state *state.IntraBlockState, results *Results) error {
	for _, p := range results.Payments {
		fee := new(uint256.Int)
		fee.SetFromBig(p.Fee)
		state.AddBalance(p.Coinbase, fee)
	}
	tFee := getFee(state, feeHash.total)
	aFee := getFee(state, feeHash.accel)
	cFee := getFee(state, feeHash.committee)

	setFee(state, feeHash.total, big.NewInt(0))
	setFee(state, feeHash.accel, big.NewInt(0))
	setFee(state, feeHash.committee, big.NewInt(0))

	setFee(state, feeRecord.total, tFee)
	setFee(state, feeRecord.accel, aFee)
	setFee(state, feeRecord.committee, cFee)
	return nil
}

func totalStake(committeeMembers []committee.MemberInfo) *big.Int {
	sum := big.NewInt(0)
	for _, commMember := range committeeMembers {
		sum.Add(sum, commMember.Stake)
	}
	return sum
}

func totalAccelStake(accelInfos []committee.AccelInfo) *big.Int {
	sum := big.NewInt(0)
	for _, accelMember := range accelInfos {
		sum.Add(sum, accelMember.Stake)
	}
	return sum
}

func getResults(commInfo *committee.CommInfo, state *state.IntraBlockState, hash feeHashRecord) (*Results, error) {
	totalFee := getFee(state, hash.total)
	accelFee := getFee(state, hash.accel)
	committeeFee := getFee(state, hash.committee)

	results := &Results{
		Payments: make([]Payment, 0),
	}
	totalStake := totalStake(commInfo.MemberInfo)
	if totalStake.Cmp(common.Big0) == 1 {
		// give out money to the committee members
		for _, commMember := range commInfo.MemberInfo {
			// Since committeeFee may not be divisible by totalStake, it is possible that some
			// fee will remain after integer division. As the result, total commFee might not
			// sum up to committeeFee.
			commFee := mulDiv(committeeFee, commMember.Stake, totalStake)
			results.AddValue(&commMember.Coinbase, commFee)
		}
	}

	totalAccel := totalAccelStake(commInfo.AccelInfo)
	if totalAccel.Cmp(common.Big0) > 0 {
		// give out money to all the accelerators
		for _, accel := range commInfo.AccelInfo {
			accelFee := mulDiv(accelFee, accel.Stake, totalAccel)
			results.AddValue(&accel.Coinbase, accelFee)
		}
	}

	// give out the rest of the money to Thunder Foundation account.
	remainingFee := big.NewInt(0).Sub(totalFee, results.TotalFees())
	if remainingFee.Sign() < 0 {
		debug.Bug("Fee computation produced negative value for accelerator")
	}
	results.AddValue(&ttCommon.ThunderCoreFundationAddress, remainingFee)

	results.Log(logger)
	return results, nil
}

func GetPreviousDistribution(commInfo *committee.CommInfo, state *state.IntraBlockState) (*Results, error) {
	return getResults(commInfo, state, feeRecord)
}

func getCurrentDistribution(commInfo *committee.CommInfo, state *state.IntraBlockState) (*Results, error) {
	return getResults(commInfo, state, feeHash)
}

func mulDiv(initial *big.Int, multiplier *big.Int, divisor *big.Int) *big.Int {
	result := new(big.Int).Mul(initial, multiplier)
	result.Quo(result, divisor)
	return result
}
