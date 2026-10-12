package mutator

import (
	"encoding/binary"
	"math/rand"
	"strings"
)

type Strategy int

const (
	StratBitFlip Strategy = iota
	StratByteInsert
	StratBoundary
	StratFormatString
	StratRepeat
	StratTruncate
	StratDictionary
	StratArithmetic
	StratBlockSwap
	StratHavoc
)

var stratNames = map[string]Strategy{
	"bitflip":    StratBitFlip,
	"byteinsert": StratByteInsert,
	"boundary":   StratBoundary,
	"format":     StratFormatString,
	"repeat":     StratRepeat,
	"truncate":   StratTruncate,
	"dictionary": StratDictionary,
	"arithmetic": StratArithmetic,
	"blockswap":  StratBlockSwap,
	"havoc":      StratHavoc,
}

func StrategyFromName(name string) (Strategy, bool) {
	s, ok := stratNames[strings.ToLower(name)]
	return s, ok
}

func DefaultStrategies() []Strategy {
	return []Strategy{
		StratBitFlip, StratByteInsert, StratBoundary,
		StratFormatString, StratRepeat, StratTruncate,
	}
}

func (s Strategy) String() string {
	for name, strat := range stratNames {
		if strat == s {
			return name
		}
	}
	return "unknown"
}

type Mutator struct {
	strategies []Strategy
	dictionary [][]byte
	rng        *rand.Rand
}

func New(strategies []Strategy) *Mutator {
	return &Mutator{
		strategies: strategies,
		rng:        rand.New(rand.NewSource(rand.Int63())),
	}
}

func (m *Mutator) SetDictionary(entries []string) {
	m.dictionary = make([][]byte, len(entries))
	for i, e := range entries {
		m.dictionary[i] = []byte(e)
	}
}

func (m *Mutator) Mutate(input []byte) ([]byte, Strategy) {
	strat := m.strategies[m.rng.Intn(len(m.strategies))]
	data := make([]byte, len(input))
	copy(data, input)

	switch strat {
	case StratBitFlip:
		return m.bitFlip(data), strat
	case StratByteInsert:
		return m.byteInsert(data), strat
	case StratBoundary:
		return m.boundary(data), strat
	case StratFormatString:
		return m.formatString(data), strat
	case StratRepeat:
		return m.repeat(data), strat
	case StratTruncate:
		return m.truncate(data), strat
	case StratDictionary:
		return m.dictionaryInsert(data), strat
	case StratArithmetic:
		return m.arithmetic(data), strat
	case StratBlockSwap:
		return m.blockSwap(data), strat
	case StratHavoc:
		return m.havoc(data), strat
	default:
		return m.bitFlip(data), StratBitFlip
	}
}

func (m *Mutator) bitFlip(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	numFlips := m.rng.Intn(8) + 1
	for i := 0; i < numFlips; i++ {
		pos := m.rng.Intn(len(data))
		bit := byte(1 << uint(m.rng.Intn(8)))
		data[pos] ^= bit
	}
	return data
}

func (m *Mutator) byteInsert(data []byte) []byte {
	if len(data) == 0 {
		return []byte{byte(m.rng.Intn(256))}
	}
	pos := m.rng.Intn(len(data) + 1)
	count := m.rng.Intn(16) + 1
	insert := make([]byte, count)
	for i := range insert {
		insert[i] = byte(m.rng.Intn(256))
	}
	result := make([]byte, 0, len(data)+count)
	result = append(result, data[:pos]...)
	result = append(result, insert...)
	result = append(result, data[pos:]...)
	return result
}

var boundaryValues = [][]byte{
	{0x00},
	{0xFF},
	{0x00, 0x00},
	{0xFF, 0xFF},
	{0x7F, 0xFF},
	{0x80, 0x00},
	{0x00, 0x00, 0x00, 0x00},
	{0xFF, 0xFF, 0xFF, 0xFF},
	{0x7F, 0xFF, 0xFF, 0xFF},
	{0x80, 0x00, 0x00, 0x00},
}

func (m *Mutator) boundary(data []byte) []byte {
	if len(data) == 0 {
		return boundaryValues[m.rng.Intn(len(boundaryValues))]
	}
	bv := boundaryValues[m.rng.Intn(len(boundaryValues))]
	pos := m.rng.Intn(len(data))
	for i, b := range bv {
		if pos+i < len(data) {
			data[pos+i] = b
		}
	}
	return data
}

var fmtStrings = [][]byte{
	[]byte("%s%s%s%s%s%s%s%s%s%s"),
	[]byte("%n%n%n%n%n%n%n%n%n%n"),
	[]byte("%x%x%x%x%x%x%x%x%x%x"),
	[]byte("%d%d%d%d%d%d%d%d%d%d"),
	[]byte("%.16384d"),
	[]byte("%99999999s"),
	[]byte("AAAA%08x.%08x.%08x.%08x"),
}

func (m *Mutator) formatString(data []byte) []byte {
	fs := fmtStrings[m.rng.Intn(len(fmtStrings))]
	if len(data) == 0 {
		return fs
	}
	pos := m.rng.Intn(len(data))
	result := make([]byte, 0, pos+len(fs))
	result = append(result, data[:pos]...)
	result = append(result, fs...)
	return result
}

func (m *Mutator) repeat(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	chunkSize := m.rng.Intn(len(data)) + 1
	if chunkSize > 64 {
		chunkSize = 64
	}
	start := m.rng.Intn(len(data))
	end := start + chunkSize
	if end > len(data) {
		end = len(data)
	}
	chunk := data[start:end]
	reps := m.rng.Intn(128) + 2
	result := make([]byte, 0, len(data)+len(chunk)*reps)
	result = append(result, data[:end]...)
	for i := 0; i < reps; i++ {
		result = append(result, chunk...)
	}
	result = append(result, data[end:]...)
	return result
}

func (m *Mutator) truncate(data []byte) []byte {
	if len(data) <= 1 {
		return data
	}
	cutPoint := m.rng.Intn(len(data)-1) + 1
	return data[:cutPoint]
}

func (m *Mutator) dictionaryInsert(data []byte) []byte {
	if len(m.dictionary) == 0 {
		return m.bitFlip(data)
	}
	word := m.dictionary[m.rng.Intn(len(m.dictionary))]
	if len(data) == 0 {
		return word
	}
	pos := m.rng.Intn(len(data))
	result := make([]byte, 0, len(data)+len(word))
	result = append(result, data[:pos]...)
	result = append(result, word...)
	result = append(result, data[pos:]...)
	return result
}

func (m *Mutator) arithmetic(data []byte) []byte {
	if len(data) < 2 {
		return m.bitFlip(data)
	}
	pos := m.rng.Intn(len(data) - 1)
	val := binary.BigEndian.Uint16([]byte{data[pos], data[pos+1]})
	delta := int16(m.rng.Intn(71)) - 35
	val = uint16(int16(val) + delta)
	data[pos] = byte(val >> 8)
	data[pos+1] = byte(val)
	return data
}

func (m *Mutator) blockSwap(data []byte) []byte {
	if len(data) < 4 {
		return m.bitFlip(data)
	}
	blockLen := m.rng.Intn(len(data)/2) + 1
	if blockLen > 32 {
		blockLen = 32
	}
	pos1 := m.rng.Intn(len(data) - blockLen)
	pos2 := m.rng.Intn(len(data) - blockLen)
	for i := 0; i < blockLen; i++ {
		data[pos1+i], data[pos2+i] = data[pos2+i], data[pos1+i]
	}
	return data
}

func (m *Mutator) havoc(data []byte) []byte {
	rounds := m.rng.Intn(8) + 2
	for i := 0; i < rounds; i++ {
		switch m.rng.Intn(6) {
		case 0:
			data = m.bitFlip(data)
		case 1:
			data = m.byteInsert(data)
		case 2:
			data = m.boundary(data)
		case 3:
			data = m.arithmetic(data)
		case 4:
			data = m.truncate(data)
		case 5:
			data = m.blockSwap(data)
		}
	}
	return data
}
