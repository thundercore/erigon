package common

import (
	"crypto/sha256"

	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
	"github.com/ledgerwatch/erigon/crypto"
)

var (
	DefaultCoinbaseAddress      = common.HexToAddress("0xc4F3c85Bb93F33A485344959CF03002B63D7c4E3")
	ThunderCoreFundationAddress = common.HexToAddress("0x0000000000000000000000000000001234567989")

	commElectionTPCHash = sha256.Sum256([]byte("Thunder_CommitteeElection"))
	// CommElectionTPCAddress is 0x30d87bd4D1769437880c64A543bB649a693EB348
	CommElectionTPCAddress = common.BytesToAddress(commElectionTPCHash[:20])

	vaultTPCHash = sha256.Sum256([]byte("Thunder_Vault"))
	// VaultTPCAddress is 0xEC45c94322EaFEEB2Cf441Cd1aB9e81E58901a08
	VaultTPCAddress = common.BytesToAddress(vaultTPCHash[:20])

	randomTPCHash = sha256.Sum256([]byte("Thunder_Random"))
	// RandomTPCAddress is 0x8cC9C2e145d3AA946502964B1B69CE3cD066A9C7
	RandomTPCAddress = common.BytesToAddress(randomTPCHash[:20])

	blockSnTPCHash = sha256.Sum256([]byte("Thunder_BlockSn"))
	// BlockSnTPCAddress is 0xd5891E5D906480f4215c78778B9FCEc909B04235
	BlockSnTPCAddress = common.BytesToAddress(blockSnTPCHash[:20])

	PSTAddr common.Address
)

const (
	HashLength    = 32
	AddressLength = 20
)

func init() {
	pstKey, err := crypto.HexToECDSA("FCD8B370EB179F9BEA4D205C4130AFDEC9EB6A4BBFAF02477EC9C8AFC14BAADC")
	if err != nil {
		debug.Fatal("PST key error")
	}
	PSTAddr = crypto.PubkeyToAddress(pstKey.PublicKey)
}
