package capture

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type PacketDirection int

const (
	DirSend PacketDirection = iota
	DirRecv
)

type Packet struct {
	Timestamp time.Time
	Direction PacketDirection
	Data      []byte
	SrcPort   uint16
	DstPort   uint16
	Iteration int
	Strategy  string
}

type Capturer struct {
	packets  []*Packet
	mu       sync.Mutex
	enabled  bool
	maxStore int
}

func New(enabled bool, maxStore int) *Capturer {
	if maxStore <= 0 {
		maxStore = 100000
	}
	return &Capturer{
		enabled:  enabled,
		maxStore: maxStore,
	}
}

func (c *Capturer) Record(pkt *Packet) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.packets) >= c.maxStore {
		c.packets = c.packets[1:]
	}
	c.packets = append(c.packets, pkt)
}

func (c *Capturer) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.packets)
}

func (c *Capturer) WritePCAP(outputDir string) error {
	c.mu.Lock()
	packets := make([]*Packet, len(c.packets))
	copy(packets, c.packets)
	c.mu.Unlock()

	if len(packets) == 0 {
		return nil
	}

	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	ts := time.Now().Format("20060102_150405")
	path := filepath.Join(outputDir, fmt.Sprintf("capture_%s.pcap", ts))

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create pcap: %w", err)
	}
	defer f.Close()

	if err := writePCAPHeader(f); err != nil {
		return fmt.Errorf("write pcap header: %w", err)
	}

	for _, pkt := range packets {
		if err := writePCAPPacket(f, pkt); err != nil {
			return fmt.Errorf("write pcap packet: %w", err)
		}
	}

	log.Printf("PCAP written: %s (%d packets)", path, len(packets))
	return nil
}

func (c *Capturer) PacketsForIteration(iteration int) []*Packet {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []*Packet
	for _, pkt := range c.packets {
		if pkt.Iteration == iteration {
			result = append(result, pkt)
		}
	}
	return result
}

func writePCAPHeader(f *os.File) error {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:], 0xa1b2c3d4)  // magic
	binary.LittleEndian.PutUint16(header[4:], 2)             // major version
	binary.LittleEndian.PutUint16(header[6:], 4)             // minor version
	binary.LittleEndian.PutUint32(header[8:], 0)             // timezone
	binary.LittleEndian.PutUint32(header[12:], 0)            // sigfigs
	binary.LittleEndian.PutUint32(header[16:], 65535)        // snaplen
	binary.LittleEndian.PutUint32(header[20:], 228)          // linktype: raw IPv4
	_, err := f.Write(header)
	return err
}

func writePCAPPacket(f *os.File, pkt *Packet) error {
	payload := pkt.Data
	isTCP := true

	ipHeaderLen := 20
	tcpHeaderLen := 20
	udpHeaderLen := 8

	transportLen := tcpHeaderLen
	if !isTCP {
		transportLen = udpHeaderLen
	}

	totalLen := ipHeaderLen + transportLen + len(payload)

	ipHeader := make([]byte, ipHeaderLen)
	ipHeader[0] = 0x45
	ipHeader[1] = 0x00
	binary.BigEndian.PutUint16(ipHeader[2:], uint16(totalLen))
	ipHeader[8] = 64 // TTL
	if isTCP {
		ipHeader[9] = 6 // TCP
	} else {
		ipHeader[9] = 17 // UDP
	}

	if pkt.Direction == DirSend {
		copy(ipHeader[12:], []byte{127, 0, 0, 1})
		copy(ipHeader[16:], []byte{10, 0, 0, 1})
	} else {
		copy(ipHeader[12:], []byte{10, 0, 0, 1})
		copy(ipHeader[16:], []byte{127, 0, 0, 1})
	}

	var transportHeader []byte
	if isTCP {
		transportHeader = make([]byte, tcpHeaderLen)
		binary.BigEndian.PutUint16(transportHeader[0:], pkt.SrcPort)
		binary.BigEndian.PutUint16(transportHeader[2:], pkt.DstPort)
		transportHeader[12] = 0x50
		transportHeader[13] = 0x18 // ACK+PSH
		binary.BigEndian.PutUint16(transportHeader[14:], 65535)
	} else {
		transportHeader = make([]byte, udpHeaderLen)
		binary.BigEndian.PutUint16(transportHeader[0:], pkt.SrcPort)
		binary.BigEndian.PutUint16(transportHeader[2:], pkt.DstPort)
		binary.BigEndian.PutUint16(transportHeader[4:], uint16(udpHeaderLen+len(payload)))
	}

	packet := make([]byte, 0, totalLen)
	packet = append(packet, ipHeader...)
	packet = append(packet, transportHeader...)
	packet = append(packet, payload...)

	ts := pkt.Timestamp
	pktHeader := make([]byte, 16)
	binary.LittleEndian.PutUint32(pktHeader[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(pktHeader[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(pktHeader[8:], uint32(len(packet)))
	binary.LittleEndian.PutUint32(pktHeader[12:], uint32(len(packet)))

	if _, err := f.Write(pktHeader); err != nil {
		return err
	}
	_, err := f.Write(packet)
	return err
}
