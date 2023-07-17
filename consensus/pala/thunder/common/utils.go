package common

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
)

func MapFromJSONBytes(bytes []byte) (map[string]string, error) {
	data := map[string]string{}
	err := json.Unmarshal(bytes, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func MapFromJSONFile(filename *string) (map[string]string, error) {
	bytes, err := os.ReadFile(*filename)
	if err != nil {
		return nil, err
	}
	return MapFromJSONBytes(bytes)
}

func BytesFromJSONFile(filename, key *string) (*[]byte, error) {
	data, err := MapFromJSONFile(filename)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(data[*key])
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func Uint64ToBytes(n uint64) []byte {
	var result [8]byte
	binary.LittleEndian.PutUint64(result[:], n)
	return result[:]
}

func BytesToUint64(bytes []byte) (uint64, []byte, error) {
	if len(bytes) < 8 {
		return 0, nil, fmt.Errorf("len(bytes) = %d < 4", len(bytes))
	}
	v := binary.LittleEndian.Uint64(bytes)
	return v, bytes[8:], nil
}

func Uint32ToBytes(n uint32) []byte {
	var result [4]byte
	binary.LittleEndian.PutUint32(result[:], n)
	return result[:]
}

func BytesToUint32(bytes []byte) (uint32, []byte, error) {
	if len(bytes) < 4 {
		return 0, nil, fmt.Errorf("len(bytes) = %d < 4", len(bytes))
	}
	v := binary.LittleEndian.Uint32(bytes)
	return v, bytes[4:], nil
}

// Wei to ether
func WeiToEther(value *big.Int) *big.Int {
	return new(big.Int).Div(value, big.NewInt(1e18))
}

func BytesToUint16(bytes []byte) (uint16, []byte, error) {
	if len(bytes) < 2 {
		return 0, nil, fmt.Errorf("len(bytes) = %d < 2", len(bytes))
	}
	return binary.LittleEndian.Uint16(bytes), bytes[2:], nil
}

func BytesToString(bytes []byte) (string, []byte, error) {
	n, bytes, err := BytesToUint16(bytes)
	if err != nil {
		return "", nil, err
	}
	if len(bytes) < int(n) {
		return "", nil, fmt.Errorf("len(bytes) = %d < %d", len(bytes), n)
	}
	s := string(bytes[:n])
	return s, bytes[n:], nil
}

func StringToBytes(s string) []byte {
	bytes := []byte(s)
	return append(Uint16ToBytes(uint16(len(bytes))), bytes...)
}

func Uint16ToBytes(n uint16) []byte {
	var result [2]byte
	binary.LittleEndian.PutUint16(result[:], n)
	return result[:]
}

func ConcatCopyPreAllocate(slices [][]byte) []byte {
	var totalLen int
	for _, s := range slices {
		totalLen += len(s)
	}
	tmp := make([]byte, totalLen)
	var i int
	for _, s := range slices {
		i += copy(tmp[i:], s)
	}
	return tmp
}

// InBenchmark returns true iff the code is being run as part of a Go benchmark.
func InBenchmark() bool {
	x := flag.Lookup("test.bench")
	if x == nil {
		return false
	}
	v := x.Value.String()
	return v != ""
}
