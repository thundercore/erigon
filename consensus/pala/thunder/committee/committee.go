package committee

import (
	"encoding/json"
	"math/big"
	"os"

	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/bls"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/certificate"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
)

const (
	MaxCommSize = 512
)

var (
	ThunderCoreGenesisCommInfo                      = &CommInfo{}
	AlterCommInfo              map[string]*CommInfo = nil
)

type CommInfo struct {
	Name            string         `json:",omitempty"`
	SlowChainHeight thunder.Height // Slow chain height when committee was elected.
	AccelId         uint
	MemberInfo      []MemberInfo // Index equals committee ID.
	AccelInfo       []AccelInfo
}

type MemberInfo struct {
	Stake      *big.Int
	PubVoteKey *bls.PublicKey
	Coinbase   common.Address
	GasPrice   *big.Int
}

type AccelInfo struct {
	MemberInfo
	AccelCert  certificate.AccelCertificate
	URI        string // URI for the accelerator's CDN
	HostPort   string // host:port for this accelerator
	TxPoolAddr string // host:port for this accelerator
}

func (ci *CommInfo) FromJSON(buf []byte) error {
	if err := json.Unmarshal(buf, ci); err != nil {
		return err
	}
	return nil
}

func ReadGenesisCommInfo(path string) (*CommInfo, error) {
	g := &CommInfo{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = g.FromJSON(data)
	if err != nil {
		return nil, err
	}

	return g, nil
}

func ReadAlterCommInfo(path string) (map[string]*CommInfo, error) {
	cInfos := []*CommInfo{}
	alterCommInfo := make(map[string]*CommInfo)

	if len(path) == 0 {
		return alterCommInfo, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &cInfos); err != nil {
		return nil, err
	}
	for _, cInfo := range cInfos {
		alterCommInfo[cInfo.Name] = cInfo
	}

	return alterCommInfo, nil
}

func (ci *CommInfo) ClearingGasPrice() *big.Int {
	c := big.NewInt(0)
	for i := 0; i < len(ci.MemberInfo); i += 1 {
		if c.Cmp(ci.MemberInfo[i].GasPrice) == -1 {
			c.Set(ci.MemberInfo[i].GasPrice)
		}
	}
	return c
}

// AccelGasPrice returns the gas price of the current accelerator.
func (ci *CommInfo) AccelGasPrice() *big.Int {
	return new(big.Int).Set(ci.AccelInfo[ci.AccelId].GasPrice)
}

func (ci *CommInfo) Clone() *CommInfo {
	bytes := ci.ToJSON()
	newCi := CommInfo{}
	newCi.FromJSON(bytes)
	return &newCi
}

func (ci *CommInfo) ToJSON() []byte {
	buf, err := json.MarshalIndent(ci, "", " ")
	if err != nil {
		debug.Bug("Encoding of CommInfo failed: %s (%v)", err, ci)
	}
	return buf
}

func (ci *CommInfo) NumAccel() int {
	return len(ci.AccelInfo)
}

func (ci *CommInfo) NumCommittee() int {
	return len(ci.MemberInfo)
}
