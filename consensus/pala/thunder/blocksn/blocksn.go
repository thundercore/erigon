package blocksn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ledgerwatch/erigon/common"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/debug"
)

func BytesToUint32(bytes []byte) (uint32, []byte, error) {
	if len(bytes) < 4 {
		return 0, nil, fmt.Errorf("len(bytes) = %d < 4", len(bytes))
	}
	v := binary.LittleEndian.Uint32(bytes)
	return v, bytes[4:], nil
}

func NewEpochFromBytes(bytes []byte) (Epoch, []byte, error) {
	if len(bytes) < 8 {
		msg := fmt.Sprintf("Invalid input: the length (%d) is less than 8", len(bytes))
		return Epoch{}, bytes, errors.New(msg)
	}

	var err error
	var tmp uint32
	tmp, bytes, err = BytesToUint32(bytes)
	if err != nil {
		return Epoch{}, nil, err
	}
	e := Epoch{Session(tmp), 0}
	e.E, bytes, err = BytesToUint32(bytes)
	if err != nil {
		return Epoch{}, nil, err
	}
	return e, bytes, nil
}

func NewBlockSnFromBytes(bytes []byte) (BlockSn, []byte, error) {
	if len(bytes) < 12 {
		msg := fmt.Sprintf("Invalid input: the length (%d) is less than 12", len(bytes))
		return BlockSn{}, bytes, errors.New(msg)
	}

	e, bytes, err := NewEpochFromBytes(bytes)
	if err != nil {
		return BlockSn{}, nil, err
	}

	s, bytes, err := BytesToUint32(bytes)
	if err != nil {
		return BlockSn{}, nil, err
	}
	return BlockSn{e, s}, bytes, nil
}

func decodeBlockSnFromBytes(data []byte) (parentSn, sn BlockSn, err error) {
	sn, data, err = NewBlockSnFromBytes(data)
	if err != nil {
		return BlockSn{}, BlockSn{}, err
	}

	parentSn, _, err = NewBlockSnFromBytes(data)
	if err != nil {
		return BlockSn{}, BlockSn{}, err
	}

	return parentSn, sn, err
}

func DecodeBlockSnFromNumber(number *big.Int) (BlockSn, BlockSn, error) {
	return decodeBlockSnFromBytes(common.LeftPadBytes(number.Bytes(), 24))
}

type IIsPala interface {
	IsPala(blockNumber uint64) bool
}

func GetBlockSnFromDifficulty(difficulty, blockNumber *big.Int, pala IIsPala) BlockSn {
	if pala.IsPala(blockNumber.Uint64()) {
		_, sn, err := DecodeBlockSnFromNumber(difficulty)
		if err != nil {
			debug.Bug("Cannot decode blocksn from difficulty (%v).", difficulty)
			return BlockSn{}
		}
		return sn
	} else {
		return NewBlockSn(0, 0, uint32(blockNumber.Uint64()))
	}
}

func GetSessionFromDifficulty(difficulty, blockNumber *big.Int, pala IIsPala) uint32 {
	if pala == nil {
		return 0
	}
	if pala.IsPala(blockNumber.Uint64()) {
		_, sn, err := DecodeBlockSnFromNumber(difficulty)
		if err != nil {
			return 0
		}
		return uint32(sn.Epoch.Session)
	} else {
		return 0
	}
}

func GetGenesisBlockSn() BlockSn {
	return BlockSn{Epoch{}, 1}
}

func encodeBlockSnToBytes(parentSn, sn BlockSn) []byte {
	return append(sn.ToBytes(), parentSn.ToBytes()...)
}

func EncodeBlockSnToNumber(parentSn, sn BlockSn) *big.Int {
	return new(big.Int).SetBytes(encodeBlockSnToBytes(parentSn, sn))
}
