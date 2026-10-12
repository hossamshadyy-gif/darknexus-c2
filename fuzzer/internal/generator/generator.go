package generator

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
)

type FieldType int

const (
	FieldRaw FieldType = iota
	FieldUint8
	FieldUint16BE
	FieldUint16LE
	FieldUint32BE
	FieldUint32LE
	FieldString
	FieldBytes
	FieldLength
	FieldChoice
	FieldRepeat
)

type Field struct {
	Name      string
	Type      FieldType
	Value     []byte
	MinLen    int
	MaxLen    int
	Choices   [][]byte
	SubFields []*Field
	RepeatMin int
	RepeatMax int
	LengthOf  string
	Fuzzable  bool
}

type Grammar struct {
	Name   string
	Fields []*Field
}

type Generator struct {
	grammars map[string]*Grammar
	rng      *rand.Rand
}

func New() *Generator {
	return &Generator{
		grammars: make(map[string]*Grammar),
		rng:      rand.New(rand.NewSource(rand.Int63())),
	}
}

func (g *Generator) AddGrammar(grammar *Grammar) {
	g.grammars[grammar.Name] = grammar
}

func (g *Generator) Generate(name string) ([]byte, error) {
	grammar, ok := g.grammars[name]
	if !ok {
		return nil, fmt.Errorf("unknown grammar: %s", name)
	}

	var result []byte
	lengths := make(map[string]int)

	for _, field := range grammar.Fields {
		data := g.generateField(field, lengths)
		result = append(result, data...)

		if field.Name != "" {
			lengths[field.Name] = len(data)
		}
	}

	return g.fixupLengths(result, grammar.Fields, lengths), nil
}

func (g *Generator) GenerateFuzzed(name string) ([]byte, string, error) {
	grammar, ok := g.grammars[name]
	if !ok {
		return nil, "", fmt.Errorf("unknown grammar: %s", name)
	}

	fuzzableIdx := []int{}
	for i, f := range grammar.Fields {
		if f.Fuzzable {
			fuzzableIdx = append(fuzzableIdx, i)
		}
	}

	if len(fuzzableIdx) == 0 {
		data, err := g.Generate(name)
		return data, "none", err
	}

	targetIdx := fuzzableIdx[g.rng.Intn(len(fuzzableIdx))]
	targetField := grammar.Fields[targetIdx]

	var result []byte
	lengths := make(map[string]int)
	var fuzzedFieldName string

	for i, field := range grammar.Fields {
		var data []byte
		if i == targetIdx {
			data = g.fuzzField(field)
			fuzzedFieldName = field.Name
		} else {
			data = g.generateField(field, lengths)
		}
		result = append(result, data...)
		if field.Name != "" {
			lengths[field.Name] = len(data)
		}
	}

	_ = targetField
	return result, fuzzedFieldName, nil
}

func (g *Generator) generateField(field *Field, lengths map[string]int) []byte {
	switch field.Type {
	case FieldRaw:
		return append([]byte(nil), field.Value...)

	case FieldUint8:
		if field.Value != nil {
			return []byte{field.Value[0]}
		}
		return []byte{byte(g.rng.Intn(256))}

	case FieldUint16BE:
		buf := make([]byte, 2)
		if field.Value != nil {
			copy(buf, field.Value)
		} else {
			binary.BigEndian.PutUint16(buf, uint16(g.rng.Intn(65536)))
		}
		return buf

	case FieldUint16LE:
		buf := make([]byte, 2)
		if field.Value != nil {
			copy(buf, field.Value)
		} else {
			binary.LittleEndian.PutUint16(buf, uint16(g.rng.Intn(65536)))
		}
		return buf

	case FieldUint32BE:
		buf := make([]byte, 4)
		if field.Value != nil {
			copy(buf, field.Value)
		} else {
			binary.BigEndian.PutUint32(buf, g.rng.Uint32())
		}
		return buf

	case FieldUint32LE:
		buf := make([]byte, 4)
		if field.Value != nil {
			copy(buf, field.Value)
		} else {
			binary.LittleEndian.PutUint32(buf, g.rng.Uint32())
		}
		return buf

	case FieldString:
		if field.Value != nil {
			return append([]byte(nil), field.Value...)
		}
		length := field.MinLen + g.rng.Intn(field.MaxLen-field.MinLen+1)
		return g.randomString(length)

	case FieldBytes:
		length := field.MinLen + g.rng.Intn(field.MaxLen-field.MinLen+1)
		buf := make([]byte, length)
		for i := range buf {
			buf[i] = byte(g.rng.Intn(256))
		}
		return buf

	case FieldChoice:
		if len(field.Choices) == 0 {
			return nil
		}
		choice := field.Choices[g.rng.Intn(len(field.Choices))]
		return append([]byte(nil), choice...)

	case FieldRepeat:
		count := field.RepeatMin + g.rng.Intn(field.RepeatMax-field.RepeatMin+1)
		var result []byte
		for i := 0; i < count; i++ {
			for _, sub := range field.SubFields {
				result = append(result, g.generateField(sub, lengths)...)
			}
		}
		return result

	case FieldLength:
		return []byte{0, 0}

	default:
		return field.Value
	}
}

func (g *Generator) fuzzField(field *Field) []byte {
	strategy := g.rng.Intn(6)

	switch strategy {
	case 0:
		return nil
	case 1:
		return g.oversizedField(field)
	case 2:
		return g.boundaryField(field)
	case 3:
		return g.wrongTypeField(field)
	case 4:
		return g.repeatedField(field)
	case 5:
		return g.negativeField(field)
	default:
		return field.Value
	}
}

func (g *Generator) oversizedField(field *Field) []byte {
	sizes := []int{256, 1024, 4096, 65535, 131072}
	size := sizes[g.rng.Intn(len(sizes))]
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = 'A'
	}
	return buf
}

func (g *Generator) boundaryField(field *Field) []byte {
	boundaries := [][]byte{
		{0x00},
		{0xFF},
		{0x00, 0x00},
		{0xFF, 0xFF},
		{0x7F, 0xFF, 0xFF, 0xFF},
		{0x80, 0x00, 0x00, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF},
	}
	return boundaries[g.rng.Intn(len(boundaries))]
}

func (g *Generator) wrongTypeField(field *Field) []byte {
	switch field.Type {
	case FieldUint8, FieldUint16BE, FieldUint16LE, FieldUint32BE, FieldUint32LE:
		return []byte("not_a_number")
	case FieldString:
		buf := make([]byte, 16)
		for i := range buf {
			buf[i] = byte(g.rng.Intn(256))
		}
		return buf
	default:
		return []byte("%n%n%n%n%n")
	}
}

func (g *Generator) repeatedField(field *Field) []byte {
	base := field.Value
	if base == nil {
		base = []byte("A")
	}
	count := 64 + g.rng.Intn(512)
	return []byte(strings.Repeat(string(base), count))
}

func (g *Generator) negativeField(field *Field) []byte {
	switch field.Type {
	case FieldUint16BE:
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, 0xFFFF)
		return buf
	case FieldUint32BE:
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, 0xFFFFFFFF)
		return buf
	default:
		return []byte{0xFF, 0xFF, 0xFF, 0xFF}
	}
}

func (g *Generator) fixupLengths(data []byte, fields []*Field, lengths map[string]int) []byte {
	offset := 0
	for _, field := range fields {
		fieldLen := lengths[field.Name]
		if field.Type == FieldLength && field.LengthOf != "" {
			targetLen, ok := lengths[field.LengthOf]
			if ok && offset+2 <= len(data) {
				binary.BigEndian.PutUint16(data[offset:], uint16(targetLen))
			}
		}
		offset += fieldLen
	}
	return data
}

func (g *Generator) randomString(length int) []byte {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = charset[g.rng.Intn(len(charset))]
	}
	return buf
}

func DNSQueryGrammar() *Grammar {
	return &Grammar{
		Name: "dns_query",
		Fields: []*Field{
			{Name: "txid", Type: FieldUint16BE, Fuzzable: true},
			{Name: "flags", Type: FieldUint16BE, Value: []byte{0x01, 0x00}},
			{Name: "qdcount", Type: FieldUint16BE, Value: []byte{0x00, 0x01}, Fuzzable: true},
			{Name: "ancount", Type: FieldUint16BE, Value: []byte{0x00, 0x00}},
			{Name: "nscount", Type: FieldUint16BE, Value: []byte{0x00, 0x00}},
			{Name: "arcount", Type: FieldUint16BE, Value: []byte{0x00, 0x00}},
			{Name: "qname", Type: FieldChoice, Fuzzable: true, Choices: [][]byte{
				{0x04, 't', 'e', 's', 't', 0x03, 'c', '2', 'c', 0x00},
				{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00},
				{0x01, 'a', 0x01, 'b', 0x01, 'c', 0x00},
			}},
			{Name: "qtype", Type: FieldChoice, Fuzzable: true, Choices: [][]byte{
				{0x00, 0x01},
				{0x00, 0x1c},
				{0x00, 0x10},
				{0x00, 0xff},
			}},
			{Name: "qclass", Type: FieldUint16BE, Value: []byte{0x00, 0x01}},
		},
	}
}

func HTTPRequestGrammar() *Grammar {
	return &Grammar{
		Name: "http_request",
		Fields: []*Field{
			{Name: "method", Type: FieldChoice, Fuzzable: true, Choices: [][]byte{
				[]byte("GET"),
				[]byte("POST"),
				[]byte("PUT"),
				[]byte("DELETE"),
				[]byte("PATCH"),
				[]byte("OPTIONS"),
				[]byte("HEAD"),
			}},
			{Name: "sp1", Type: FieldRaw, Value: []byte(" ")},
			{Name: "path", Type: FieldChoice, Fuzzable: true, Choices: [][]byte{
				[]byte("/"),
				[]byte("/api/v1/data"),
				[]byte("/api/checkin"),
				[]byte("/api/tasks"),
				[]byte("/login"),
			}},
			{Name: "sp2", Type: FieldRaw, Value: []byte(" ")},
			{Name: "version", Type: FieldChoice, Fuzzable: true, Choices: [][]byte{
				[]byte("HTTP/1.0"),
				[]byte("HTTP/1.1"),
				[]byte("HTTP/2"),
			}},
			{Name: "crlf1", Type: FieldRaw, Value: []byte("\r\n")},
			{Name: "host_header", Type: FieldRaw, Value: []byte("Host: localhost\r\n")},
			{Name: "content_type", Type: FieldChoice, Fuzzable: true, Choices: [][]byte{
				[]byte("Content-Type: application/json\r\n"),
				[]byte("Content-Type: text/plain\r\n"),
				[]byte("Content-Type: application/x-www-form-urlencoded\r\n"),
				[]byte(""),
			}},
			{Name: "end_headers", Type: FieldRaw, Value: []byte("\r\n")},
			{Name: "body", Type: FieldChoice, Fuzzable: true, Choices: [][]byte{
				[]byte(""),
				[]byte(`{"type":"checkin","id":"fuzz"}`),
				[]byte(`{"data":"test"}`),
				[]byte("key=value&foo=bar"),
			}},
		},
	}
}
