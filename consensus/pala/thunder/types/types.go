package types

import (
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon/consensus/pala/thunder/blocksn"
)

type Type uint8

const (
	TypeNil          = Type(0)
	TypeBlock        = Type(1)
	TypeProposal     = Type(2)
	TypeVote         = Type(3)
	TypeNotarization = Type(4)
	TypeClockMsg     = Type(5)
	TypeClockMsgNota = Type(6)
	TypeHeader       = Type(7)
	TypeBlockBody    = Type(8)
)

const HashLength = 32

type Hash [HashLength]byte

// Bytes gets the byte representation of the underlying hash.
func (h Hash) Bytes() []byte { return h[:] }

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

// BytesToHash sets b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

type Message interface {
	GetType() Type
	GetBody() []byte
	GetBlockSn() blocksn.BlockSn
	GetDebugString() string
}

type Header interface {
	Message
	ImplementsHeader()
	GetHash() Hash
	GetNumber() uint64
	GetParentBlockSn() blocksn.BlockSn
}

type Block interface {
	Message

	ImplementsBlock()

	GetParentBlockSn() blocksn.BlockSn
	GetHash() Hash
	GetParentHash() Hash
	// GetNumber() returns the number (height) of this block.
	GetNumber() uint64

	// GetBodyString() returns a string to represent the block.
	// This is used for logging/testing/debugging.
	GetBodyString() string
}

type BlockDecoder interface {

	// GetNotarizations() returns the notarizations stored in the block.
	// Return nil if there is none. See comments above BlockChain for more details.
	GetNotarizations(block Block, config *chain.PalaConfig) []Notarization

	// GetClockMsgNota() returns the clock message notarization stored in the block.
	// Note that:
	// * Only the first block at each epoch contains the corresponding clock message notarization.
	// * The first epoch of each session has no clock message notarization.
	GetClockMsgNota(block Block, config *chain.PalaConfig) ClockMsgNota

	// PrehandleBlock() gives a chance to use txpool pre-calculate sender in txs
	PrehandleBlock(block Block)

	// ToRawBlock converts header and block body to block in network format.
	ToRawBlock(header []byte, body []byte) ([]byte, error)
}

type Proposal interface {
	Message

	ImplementsProposal()

	GetBlock() Block
	GetProposerId() ConsensusId
}

type Vote interface {
	Message

	ImplementsVote()

	GetVoterId() ConsensusId
}

type Notarization interface {
	Message

	ImplementsNotarization()

	GetNVote() uint16
	GetMissingVoterIdxs() []uint16
	GetBlockHash() Hash
}

type ClockMsg interface {
	Message

	ImplementsClockMsg()

	GetEpoch() blocksn.Epoch
	GetVoterId() ConsensusId
}

type ClockMsgNota interface {
	Message

	ImplementsClockMsgNota()

	GetEpoch() blocksn.Epoch
	GetNVote() uint16
}

type DataUnmarshaller interface {
	// UnmarshalBlock receives Block.GetBody() and returns Block and the rest of the bytes.
	UnmarshalBlock([]byte) (Block, []byte, error)
	// UnmarshalProposal receives Proposal.GetBody() and returns Proposal and the rest of the bytes.
	UnmarshalProposal([]byte) (Proposal, []byte, error)
	// UnmarshalVote receives Vote.GetBody() and returns Vote and the rest of the bytes.
	UnmarshalVote([]byte) (Vote, []byte, error)
	// UnmarshalNotarization receives Notarization.GetBody() and returns Notarization and
	// the rest of the bytes.
	UnmarshalNotarization([]byte) (Notarization, []byte, error)
	// UnmarshalClockMsg receives ClockMsg.GetBody() and returns ClockMsg and the rest of the bytes.
	UnmarshalClockMsg([]byte) (ClockMsg, []byte, error)
	// UnmarshalClockMsgNota receives ClockMsgNota.GetBody()
	// and returns ClockMsgNota and the rest of the bytes.
	UnmarshalClockMsgNota([]byte) (ClockMsgNota, []byte, error)
}

type Verifier interface {
	Propose(b Block) (Proposal, error)
	// IsReadyToPropose returns true if votes from `ids` are enough to make a notarization.
	IsReadyToPropose(ids []ConsensusId, session blocksn.Session) bool
	// VerifyProposal verifies |p| is signed by the eligible proposer
	// and |p|'s block should contain valid notarizations of ancestor blocks.
	// See the rule above BlockChain for details.
	VerifyProposal(p Proposal) error
	Vote(p Proposal) (Vote, error)
	VerifyVote(v Vote, r ChainReader) error
	Notarize(votes []Vote, r ChainReader) (Notarization, error)
	VerifyNotarization(n Notarization, r ChainReader) error
	VerifyNotarizationWithBlock(n Notarization, block Block) error
	NewClockMsg(e blocksn.Epoch) (ClockMsg, error)
	VerifyClockMsg(c ClockMsg) error
	NewClockMsgNota(clocks []ClockMsg) (ClockMsgNota, error)
	VerifyClockMsgNota(cn ClockMsgNota) error

	// Sign signs |bytes|.
	Sign(bytes []byte) (ConsensusId, []byte, error)
	// VerifySignature verifies |signature| is signed correctly and the signed message
	// equals to |expected|.
	VerifySignature(signature []byte, expected []byte) (id ConsensusId, isConsensusNode bool, err error)
}

type ChainReader interface {
	ContainsBlock(s blocksn.BlockSn) bool
	GetBlock(s blocksn.BlockSn) Block
	GetGenesisBlock() Block
	GetNotarization(s blocksn.BlockSn) Notarization
	GetFreshestNotarizedHead() Block
	GetFinalizedHead() Block
	DecodeBlock(b Block) ([]Notarization, ClockMsgNota)
	IsCreatingBlock() bool
	GetProposerAddresses(session blocksn.Session) map[ConsensusId]string
}
