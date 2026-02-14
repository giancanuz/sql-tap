package mysql

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/mickamy/sql-tap/proxy"
)

// MySQL command bytes.
const (
	comQuery       byte = 0x03
	comStmtPrepare byte = 0x16
	comStmtExecute byte = 0x17
	comStmtClose   byte = 0x19
)

// MySQL response packet type indicators (first byte of payload).
const (
	iOK  byte = 0x00
	iERR byte = 0xFF
	iEOF byte = 0xFE
)

// MySQL capability flags.
const (
	clientSSL          uint32 = 1 << 11
	clientDeprecateEOF uint32 = 1 << 24
)

// responseState tracks where we are in parsing a server response sequence.
type responseState int

const (
	stateIdle        responseState = iota
	stateFirstResp                 // waiting for first response to a command
	stateColumnDefs                // reading column definitions
	stateRowData                   // reading result set rows
	stateSkipPrepare               // skipping param/column def packets after StmtPrepareOK
)

// conn manages bidirectional relay and protocol parsing for a single MySQL connection.
type conn struct {
	clientConn   net.Conn
	upstreamConn net.Conn
	events       chan<- proxy.Event

	preparedStmts map[uint32]string // stmt ID -> query
	lastCommand   byte
	lastQuery     string
	lastStmtID    uint32

	activeTxID string
	nextID     uint64

	state       responseState
	skipPackets int // remaining param/column def packets to skip after StmtPrepareOK

	mu      sync.Mutex
	pending *proxy.Event
}

func newConn(clientConn, upstreamConn net.Conn, events chan<- proxy.Event) *conn {
	return &conn{
		clientConn:    clientConn,
		upstreamConn:  upstreamConn,
		events:        events,
		preparedStmts: make(map[uint32]string),
	}
}

func (c *conn) generateID() string {
	c.nextID++
	return strconv.FormatUint(c.nextID, 10)
}

// ---------------- packet I/O ----------------

// readPacket reads a single MySQL packet: 3-byte length + 1-byte sequence ID + payload.
func readPacket(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("mysql: read packet header: %w", err)
	}
	payloadLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	pkt := make([]byte, 4+payloadLen)
	copy(pkt, hdr[:])
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, pkt[4:]); err != nil {
			return nil, fmt.Errorf("mysql: read packet payload: %w", err)
		}
	}
	return pkt, nil
}

// writePacket writes a raw packet to dst.
func writePacket(dst net.Conn, pkt []byte) error {
	if _, err := dst.Write(pkt); err != nil {
		return fmt.Errorf("mysql: write packet: %w", err)
	}
	return nil
}

// payloadByte returns the first byte of the payload (the type indicator).
func payloadByte(pkt []byte) byte {
	if len(pkt) <= 4 {
		return 0
	}
	return pkt[4]
}

// payloadLen returns the payload length encoded in the header.
func payloadLen(pkt []byte) int {
	return int(pkt[0]) | int(pkt[1])<<8 | int(pkt[2])<<16
}

// readLenEncInt reads a length-encoded integer from a byte slice at offset,
// returning the value and the number of bytes consumed.
func readLenEncInt(data []byte, offset int) (uint64, int) {
	if offset >= len(data) {
		return 0, 0
	}
	switch {
	case data[offset] < 0xFB:
		return uint64(data[offset]), 1
	case data[offset] == 0xFC:
		if offset+2 >= len(data) {
			return 0, 0
		}
		return uint64(binary.LittleEndian.Uint16(data[offset+1 : offset+3])), 3
	case data[offset] == 0xFD:
		if offset+3 >= len(data) {
			return 0, 0
		}
		return uint64(data[offset+1]) | uint64(data[offset+2])<<8 | uint64(data[offset+3])<<16, 4
	case data[offset] == 0xFE:
		if offset+8 >= len(data) {
			return 0, 0
		}
		return binary.LittleEndian.Uint64(data[offset+1 : offset+9]), 9
	}
	return 0, 0
}

// clearCapabilityBits clears the given capability bits in a server greeting packet.
// The greeting layout (HandshakeV10) has a variable-length server version string,
// so we must find the NUL terminator to locate the capability flag offsets.
//
// Layout after payload[0] (protocol version):
//
//	payload[1..NUL]  server version (NUL-terminated)
//	+0  connection_id    (4 bytes)
//	+4  auth_data_1      (8 bytes)
//	+12 filler           (1 byte)
//	+13 cap_flags_lower  (2 bytes)
//	+15 charset          (1 byte)
//	+16 status_flags     (2 bytes)
//	+18 cap_flags_upper  (2 bytes)
func clearCapabilityBits(pkt []byte, bits uint32) {
	payload := pkt[4:]
	// Find end of NUL-terminated server version string starting at offset 1.
	nulIdx := bytes.IndexByte(payload[1:], 0x00)
	if nulIdx < 0 {
		return
	}
	base := 1 + nulIdx + 1 // past protocol_version byte + version string + NUL

	lowerOff := base + 13
	if lowerOff+2 > len(payload) {
		return
	}
	lower := binary.LittleEndian.Uint16(payload[lowerOff : lowerOff+2])
	lower &^= uint16(bits & 0xFFFF) //nolint:gosec // masking to 16 bits, won't overflow
	binary.LittleEndian.PutUint16(payload[lowerOff:lowerOff+2], lower)

	upperOff := base + 18
	if upperOff+2 > len(payload) {
		return
	}
	upper := binary.LittleEndian.Uint16(payload[upperOff : upperOff+2])
	upper &^= uint16(bits >> 16) //nolint:gosec // shifted to 16 bits, won't overflow
	binary.LittleEndian.PutUint16(payload[upperOff:upperOff+2], upper)
}

// clearClientCapabilityBits clears the given capability bits in a client handshake response.
// The capability flags are the first 4 bytes of the payload.
func clearClientCapabilityBits(pkt []byte, bits uint32) {
	payload := pkt[4:]
	if len(payload) < 4 {
		return
	}
	caps := binary.LittleEndian.Uint32(payload[0:4])
	caps &^= bits
	binary.LittleEndian.PutUint32(payload[0:4], caps)
}

// ---------------- handshake ----------------

// relayStartup handles the MySQL handshake/auth phase.
func (c *conn) relayStartup() error {
	// 1. Read server greeting, strip SSL and DEPRECATE_EOF capabilities.
	greeting, err := readPacket(c.upstreamConn)
	if err != nil {
		return fmt.Errorf("mysql: read greeting: %w", err)
	}
	clearCapabilityBits(greeting, clientSSL|clientDeprecateEOF)
	if err := writePacket(c.clientConn, greeting); err != nil {
		return fmt.Errorf("mysql: send greeting: %w", err)
	}

	// 2. Read client handshake response, strip DEPRECATE_EOF.
	resp, err := readPacket(c.clientConn)
	if err != nil {
		return fmt.Errorf("mysql: read handshake response: %w", err)
	}
	clearClientCapabilityBits(resp, clientDeprecateEOF)
	if err := writePacket(c.upstreamConn, resp); err != nil {
		return fmt.Errorf("mysql: send handshake response: %w", err)
	}

	// 3. Relay auth packets until OK or ERR.
	for {
		pkt, err := readPacket(c.upstreamConn)
		if err != nil {
			return fmt.Errorf("mysql: read auth: %w", err)
		}
		if err := writePacket(c.clientConn, pkt); err != nil {
			return fmt.Errorf("mysql: send auth: %w", err)
		}

		switch payloadByte(pkt) {
		case iOK:
			return nil
		case iERR:
			return errors.New("mysql: auth error from upstream")
		case 0x01: // AuthMoreData
			// caching_sha2_password fast auth success: server sends [0x01, 0x03],
			// then follows with OK. No client response needed.
			payload := pkt[4:]
			if len(payload) >= 2 && payload[1] == 0x03 {
				continue
			}
			// Full auth needed (e.g. 0x04): fall through to read client response.
		}

		// Auth switch or other auth continuation: read client response and forward.
		clientResp, err := readPacket(c.clientConn)
		if err != nil {
			return fmt.Errorf("mysql: read auth client response: %w", err)
		}
		if err := writePacket(c.upstreamConn, clientResp); err != nil {
			return fmt.Errorf("mysql: send auth client response: %w", err)
		}
	}
}

// ---------------- relay ----------------

func (c *conn) relay(ctx context.Context) error {
	if err := c.relayStartup(); err != nil {
		return fmt.Errorf("mysql: startup: %w", err)
	}

	errCh := make(chan error, 2)
	go func() { errCh <- c.relayClientToUpstream(ctx) }()
	go func() { errCh <- c.relayUpstreamToClient(ctx) }()

	err := <-errCh
	_ = c.clientConn.Close()
	_ = c.upstreamConn.Close()
	<-errCh

	return err
}

func (c *conn) relayClientToUpstream(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("mysql: client relay: %w", ctx.Err())
		}

		pkt, err := readPacket(c.clientConn)
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("mysql: receive from client: %w", err)
		}

		c.captureClientPacket(pkt)

		if err := writePacket(c.upstreamConn, pkt); err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("mysql: send to upstream: %w", err)
		}
	}
}

func (c *conn) relayUpstreamToClient(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("mysql: upstream relay: %w", ctx.Err())
		}

		pkt, err := readPacket(c.upstreamConn)
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("mysql: receive from upstream: %w", err)
		}

		c.captureUpstreamPacket(pkt)

		if err := writePacket(c.clientConn, pkt); err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("mysql: send to client: %w", err)
		}
	}
}

// ---------------- client capture ----------------

func (c *conn) captureClientPacket(pkt []byte) {
	if payloadLen(pkt) < 1 {
		return
	}
	cmd := payloadByte(pkt)
	payload := pkt[4:]

	switch cmd {
	case comQuery:
		q := string(payload[1:])
		c.lastCommand = comQuery
		c.lastQuery = q
		c.state = stateFirstResp

		r := c.detectTx(q, proxy.OpQuery)
		ev := proxy.Event{
			ID:        c.generateID(),
			Op:        r.op,
			Query:     q,
			StartTime: time.Now(),
			TxID:      r.txID,
		}
		c.mu.Lock()
		c.pending = &ev
		c.mu.Unlock()

	case comStmtPrepare:
		q := string(payload[1:])
		c.lastCommand = comStmtPrepare
		c.lastQuery = q
		c.state = stateFirstResp

	case comStmtExecute:
		c.lastCommand = comStmtExecute
		c.state = stateFirstResp

		if len(payload) >= 5 {
			stmtID := binary.LittleEndian.Uint32(payload[1:5])
			c.lastStmtID = stmtID
			q := c.preparedStmts[stmtID]
			c.lastQuery = q

			r := c.detectTx(q, proxy.OpExecute)
			ev := proxy.Event{
				ID:        c.generateID(),
				Op:        r.op,
				Query:     q,
				StartTime: time.Now(),
				TxID:      r.txID,
			}
			c.mu.Lock()
			c.pending = &ev
			c.mu.Unlock()
		}

	case comStmtClose:
		if len(payload) >= 5 {
			stmtID := binary.LittleEndian.Uint32(payload[1:5])
			delete(c.preparedStmts, stmtID)
		}
	}
}

// ---------------- upstream capture (state machine) ----------------

func (c *conn) captureUpstreamPacket(pkt []byte) {
	switch c.state {
	case stateIdle:
		return

	case stateFirstResp:
		c.handleFirstResponse(pkt)

	case stateColumnDefs:
		if isEOFPacket(pkt) {
			c.state = stateRowData
		}

	case stateRowData:
		if isEOFPacket(pkt) {
			c.finalizeResultSet(pkt)
			c.state = stateIdle
		} else if payloadByte(pkt) == iERR {
			c.finalizeError(pkt)
			c.state = stateIdle
		}

	case stateSkipPrepare:
		c.skipPackets--
		if c.skipPackets <= 0 {
			c.state = stateIdle
		}
	}
}

func (c *conn) handleFirstResponse(pkt []byte) {
	first := payloadByte(pkt)

	switch {
	case first == iOK && c.lastCommand != comStmtPrepare:
		// OK packet for a non-prepare command.
		c.finalizeOK(pkt)
		c.state = stateIdle

	case first == iERR:
		c.finalizeError(pkt)
		c.state = stateIdle

	case first == iOK && c.lastCommand == comStmtPrepare:
		// COM_STMT_PREPARE_OK response.
		c.handleStmtPrepareOK(pkt)

	default:
		// Column count packet: transition to reading column definitions.
		c.state = stateColumnDefs
	}
}

func (c *conn) handleStmtPrepareOK(pkt []byte) {
	payload := pkt[4:]
	// COM_STMT_PREPARE_OK: status(1) + stmt_id(4) + num_columns(2) + num_params(2) + reserved(1) + warning_count(2)
	if len(payload) < 12 {
		c.state = stateIdle
		return
	}

	stmtID := binary.LittleEndian.Uint32(payload[1:5])
	numColumns := binary.LittleEndian.Uint16(payload[5:7])
	numParams := binary.LittleEndian.Uint16(payload[7:9])

	c.preparedStmts[stmtID] = c.lastQuery

	// We need to skip param defs + EOF + column defs + EOF.
	skip := 0
	if numParams > 0 {
		skip += int(numParams) + 1 // param defs + EOF
	}
	if numColumns > 0 {
		skip += int(numColumns) + 1 // column defs + EOF
	}
	c.skipPackets = skip
	if skip > 0 {
		c.state = stateSkipPrepare
	} else {
		c.state = stateIdle
	}
}

func (c *conn) finalizeOK(pkt []byte) {
	c.mu.Lock()
	ev := c.pending
	c.pending = nil
	c.mu.Unlock()
	if ev == nil {
		return
	}
	ev.Duration = time.Since(ev.StartTime)

	// Parse affected_rows from OK packet.
	payload := pkt[4:]
	if len(payload) > 1 {
		rows, _ := readLenEncInt(payload, 1)
		ev.RowsAffected = int64(rows) //nolint:gosec // practically won't overflow
	}

	c.emitEvent(*ev)
}

func (c *conn) finalizeError(pkt []byte) {
	c.mu.Lock()
	ev := c.pending
	c.pending = nil
	c.mu.Unlock()
	if ev == nil {
		return
	}
	ev.Duration = time.Since(ev.StartTime)

	// Parse error message: ERR_Packet = 0xFF + errno(2) + '#' + sqlstate(5) + message
	payload := pkt[4:]
	if len(payload) > 9 && payload[3] == '#' {
		ev.Error = string(payload[9:])
	} else if len(payload) > 3 {
		ev.Error = string(payload[3:])
	}

	c.emitEvent(*ev)
}

func (c *conn) finalizeResultSet(_ []byte) {
	c.mu.Lock()
	ev := c.pending
	c.pending = nil
	c.mu.Unlock()
	if ev == nil {
		return
	}
	ev.Duration = time.Since(ev.StartTime)

	// Parse affected_rows from EOF packet (which has status flags but no row count).
	// For SELECT, rows affected is typically 0.
	c.emitEvent(*ev)
}

// isEOFPacket returns true if the packet is an EOF packet (0xFE with payload < 9 bytes).
func isEOFPacket(pkt []byte) bool {
	return payloadByte(pkt) == iEOF && payloadLen(pkt) < 9
}

// ---------------- transaction detection ----------------

type txDetectResult struct {
	txID string
	op   proxy.Op
}

func (c *conn) detectTx(query string, defaultOp proxy.Op) txDetectResult {
	upper := strings.ToUpper(strings.TrimSpace(query))
	switch {
	case strings.HasPrefix(upper, "BEGIN"), strings.HasPrefix(upper, "START TRANSACTION"):
		c.activeTxID = uuid.New().String()
		return txDetectResult{txID: c.activeTxID, op: proxy.OpBegin}
	case strings.HasPrefix(upper, "COMMIT"):
		prev := c.activeTxID
		c.activeTxID = ""
		return txDetectResult{txID: prev, op: proxy.OpCommit}
	case strings.HasPrefix(upper, "ROLLBACK"):
		prev := c.activeTxID
		c.activeTxID = ""
		return txDetectResult{txID: prev, op: proxy.OpRollback}
	}
	return txDetectResult{txID: c.activeTxID, op: defaultOp}
}

func (c *conn) emitEvent(ev proxy.Event) {
	select {
	case c.events <- ev:
	default:
	}
}

func isClosedErr(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return netErr.Err.Error() == "use of closed network connection"
	}
	return strings.Contains(err.Error(), "closed")
}
