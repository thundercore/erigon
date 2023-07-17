package precompile

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/common"
	ttCommon "github.com/ledgerwatch/erigon/consensus/pala/thunder/common"
	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
)

// ByteList is a list implementation inside of statedb.
type ByteList struct {
	// account address where the ByteList resides
	account common.Address
	// statedb where data is stored
	statedb evmtypes.IntraBlockState

	// offset in the account storage where the ByteList resides
	// TODO change this to string and rename to prefix
	prefix []byte
}

// length is stored at sha256(prefix+lengthPrefix)
// size of entry i is stored at sha256(prefix+sizePrefix+i)
// jth 32 byte value of entry i is stored at sha256(prefix+sizePrefix+i*MaxInt64+j)
var (
	lengthPrefix = []byte{'l'}
	sizePrefix   = []byte{'s'}
	dataPrefix   = []byte{'d'}
)

// NewByteList creates a new ByteList at the given account and offset
// This will assume the structure of the data at the given offset is a ByteList.
// You'll in a lot of trouble if it's not.
func NewByteList(statedb evmtypes.IntraBlockState, account common.Address, prefix string) *ByteList {
	return &ByteList{
		account: account,
		statedb: statedb,
		prefix:  []byte(prefix),
	}
}

// hashesToBytes converts a hash slice to a byte slice
func hashesToBytes(hashes []common.Hash, sz int64) (r []byte) {
	r = make([]byte, sz)
	// now write the byte array itself
	for i := int64(0); i*ttCommon.HashLength < sz; i++ {
		endBytes := (i + 1) * ttCommon.HashLength
		if endBytes > sz {
			endBytes = sz
		}
		copy(r[i*ttCommon.HashLength:endBytes],
			hashes[i].Bytes()[0:endBytes-i*ttCommon.HashLength])
	}
	return
}

func (bl *ByteList) lengthLoc() common.Hash {
	return common.Hash(sha256.Sum256(append(bl.prefix, lengthPrefix...)))
}

func (bl *ByteList) entrySizeLoc(index int64) common.Hash {
	return common.Hash(sha256.Sum256(
		append(bl.prefix, append(sizePrefix, big.NewInt(index).Bytes()...)...)))
}

func (bl *ByteList) entryDataLoc(entryIndex int64, dataIndex int64) common.Hash {
	// using 32 bytes for both entryIndex and dataIndex irrespective of value ensures
	// (12, 3) != (1, 23)
	key := make([]byte, len(bl.prefix)+len(dataPrefix)+16)
	copy(key, bl.prefix)
	copy(key[len(bl.prefix):], dataPrefix)
	offset := len(bl.prefix) + len(dataPrefix)
	binary.LittleEndian.PutUint64(key[offset:], uint64(entryIndex))
	binary.LittleEndian.PutUint64(key[offset+8:], uint64(dataIndex))
	return common.Hash(sha256.Sum256(key))
}

// Length returns the length of the ByteList
func (bl *ByteList) Length() int64 {
	out := new(uint256.Int)
	lengthLoc := bl.lengthLoc()
	bl.statedb.GetState(bl.account, &lengthLoc, out)

	return out.ToBig().Int64()
}

// byteSizeToHashSize converts byte length to number of 32 byte hashes it will take up
func byteSizeToHashSize(l int64) int64 {
	// ceiling( n/m ) = floor( n-1/m ) + 1
	return (l-1)/ttCommon.HashLength + 1
}

// ToSlice converts a StateDB ByteList to a []byte slice
// This function does no error checking on data formatting so be sure you only call it
// on valid ByteSlices.
// TODO maybe add some error checking and return with an error
func (bl *ByteList) ToSlice() (r [][]byte) {
	entries := bl.Length()

	r = make([][]byte, entries)

	for i := int64(0); i < entries; i++ {
		// length in bytes of the data
		l := new(uint256.Int)
		entrySizeLoc := bl.entrySizeLoc(i)
		bl.statedb.GetState(bl.account, &entrySizeLoc, l)
		n := byteSizeToHashSize(l.ToBig().Int64())

		// read all hashes
		hashes := make([]common.Hash, n)
		for j := int64(0); j < n; j++ {
			hash := new(uint256.Int)
			entryDataLoc := bl.entryDataLoc(i, j)
			bl.statedb.GetState(bl.account, &entryDataLoc, hash)

			hashes[j] = common.BytesToHash(hash.Bytes())
		}

		// convert the hashes to []byte
		r[i] = hashesToBytes(hashes, l.ToBig().Int64())
	}
	return
}

// Append adds a byte slice to the ByteList
func (bl *ByteList) Append(val []byte) {
	sz := int64(len(val))

	// increase the total length of the list
	l := bl.Length()
	loc := bl.lengthLoc()
	state := uint256.NewInt(0).Add(uint256.NewInt(uint64(l)), uint256.NewInt(1))

	bl.statedb.SetState(bl.account,
		&loc,
		*state)

	entrySizeLoc := bl.entrySizeLoc(l)

	// write the size
	bl.statedb.SetState(bl.account,
		&entrySizeLoc,
		*uint256.NewInt(uint64(sz)))

	// now write the byte array itself
	for i := int64(0); i*ttCommon.HashLength < sz; i++ {
		endBytes := i*ttCommon.HashLength + ttCommon.HashLength
		if endBytes > sz {
			endBytes = sz
		}
		writeme := make([]byte, ttCommon.HashLength)
		copy(writeme[0:endBytes-i*ttCommon.HashLength], val[i*ttCommon.HashLength:endBytes])

		entryDataLoc := bl.entryDataLoc(l, i)
		data := uint256.NewInt(0).SetBytes(writeme)

		bl.statedb.SetState(bl.account,
			&entryDataLoc,
			*data)
		//fmt.Println("wrote ", val[i*32:endBytes])
	}
}

// Clear clears the ByteList
func (bl *ByteList) Clear() {

	// clear all entries in statedb
	entries := bl.Length()
	for i := int64(0); i < entries; i++ {
		// cache the size and clear it
		entrySizeLoc := bl.entrySizeLoc(i)
		l := new(uint256.Int)
		bl.statedb.GetState(bl.account, &entrySizeLoc, l)
		bl.statedb.SetState(bl.account, &entrySizeLoc, uint256.Int{})

		// clear the data
		n := byteSizeToHashSize(l.ToBig().Int64())
		for j := int64(0); j < n; j++ {
			entryDataLoc := bl.entryDataLoc(i, j)

			bl.statedb.SetState(bl.account, &entryDataLoc, uint256.Int{})
		}
	}

	lengthLoc := bl.lengthLoc()

	// Set the length of the list to 0
	bl.statedb.SetState(bl.account, &lengthLoc, *uint256.NewInt(0))
}
