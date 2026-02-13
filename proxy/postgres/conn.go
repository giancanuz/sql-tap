package postgres

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	pgproto "github.com/jackc/pgproto3/v2"

	"github.com/mickamy/sql-tap/proxy"
)

// encoder is satisfied by both FrontendMessage and BackendMessage.
type encoder interface {
	Encode(dst []byte) ([]byte, error)
}

// conn manages bidirectional relay and protocol parsing for a single connection.
type conn struct {
	client   *pgproto.Backend  // reads FrontendMessages from client
	upstream *pgproto.Frontend // reads BackendMessages from upstream

	clientConn   net.Conn
	upstreamConn net.Conn
	events       chan<- proxy.Event

	// Extended query state.
	preparedStmts map[string]string // stmt name -> query
	lastParse     string            // query from most recent Parse
	lastBindArgs  []string          // args from most recent Bind
	lastBindStmt  string            // stmt name from most recent Bind
	executeStart  time.Time         // when Execute started

	// Transaction tracking.
	activeTxID string
	nextID     uint64
}

func newConn(clientConn, upstreamConn net.Conn, events chan<- proxy.Event) *conn {
	return &conn{
		client:        pgproto.NewBackend(pgproto.NewChunkReader(clientConn), clientConn),
		upstream:      pgproto.NewFrontend(pgproto.NewChunkReader(upstreamConn), upstreamConn),
		clientConn:    clientConn,
		upstreamConn:  upstreamConn,
		events:        events,
		preparedStmts: make(map[string]string),
	}
}

func (c *conn) generateID() string {
	c.nextID++
	return strconv.FormatUint(c.nextID, 10)
}

// encodeAndWrite encodes a protocol message and writes it to dst.
func encodeAndWrite(dst net.Conn, msg encoder) error {
	buf, err := msg.Encode(nil)
	if err != nil {
		return fmt.Errorf("postgres: encode: %w", err)
	}
	_, err = dst.Write(buf)
	return err
}

// relay handles the startup phase and then enters bidirectional message relay.
func (c *conn) relay(ctx context.Context) error {
	if err := c.relayStartup(); err != nil {
		return fmt.Errorf("postgres: startup: %w", err)
	}

	errCh := make(chan error, 2)

	go func() { errCh <- c.relayClientToUpstream(ctx) }()
	go func() { errCh <- c.relayUpstreamToClient(ctx) }()

	// Wait for the first goroutine to finish (connection closed or error).
	err := <-errCh
	// Close both sides to unblock the other goroutine.
	_ = c.clientConn.Close()
	_ = c.upstreamConn.Close()
	// Wait for the second goroutine.
	<-errCh

	return err
}

// relayStartup copies the startup/auth phase, parsing only enough to detect ReadyForQuery.
func (c *conn) relayStartup() error {
	startupMsg, err := c.client.ReceiveStartupMessage()
	if err != nil {
		return fmt.Errorf("postgres: receive startup: %w", err)
	}

	if err := encodeAndWrite(c.upstreamConn, startupMsg); err != nil {
		return fmt.Errorf("postgres: send startup: %w", err)
	}

	for {
		msg, err := c.upstream.Receive()
		if err != nil {
			return fmt.Errorf("postgres: receive auth: %w", err)
		}

		if err := encodeAndWrite(c.clientConn, msg); err != nil {
			return fmt.Errorf("postgres: send auth: %w", err)
		}

		switch msg.(type) {
		case *pgproto.ReadyForQuery:
			return nil
		case *pgproto.ErrorResponse:
			return fmt.Errorf("postgres: auth error from upstream")
		}
	}
}

// relayClientToUpstream reads messages from the client, captures info, and forwards to upstream.
func (c *conn) relayClientToUpstream(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		msg, err := c.client.Receive()
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("postgres: receive from client: %w", err)
		}

		c.captureClientMsg(msg)

		if err := encodeAndWrite(c.upstreamConn, msg); err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("postgres: send to upstream: %w", err)
		}
	}
}

// relayUpstreamToClient reads messages from upstream, captures info, and forwards to client.
func (c *conn) relayUpstreamToClient(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		msg, err := c.upstream.Receive()
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("postgres: receive from upstream: %w", err)
		}

		c.captureUpstreamMsg(msg)

		if err := encodeAndWrite(c.clientConn, msg); err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("postgres: send to client: %w", err)
		}
	}
}

func (c *conn) captureClientMsg(msg pgproto.FrontendMessage) {
	switch m := msg.(type) {
	case *pgproto.Query:
		c.handleSimpleQuery(m)
	case *pgproto.Parse:
		c.handleParse(m)
	case *pgproto.Bind:
		c.handleBind(m)
	case *pgproto.Execute:
		c.handleExecute()
	}
}

func (c *conn) captureUpstreamMsg(msg pgproto.BackendMessage) {
	switch m := msg.(type) {
	case *pgproto.CommandComplete:
		c.handleCommandComplete(m)
	case *pgproto.ErrorResponse:
		c.handleErrorResponse(m)
	}
}

func (c *conn) handleSimpleQuery(m *pgproto.Query) {
	q := m.String
	c.detectTx(q)

	ev := proxy.Event{
		ID:        c.generateID(),
		Op:        proxy.OpQuery,
		Query:     q,
		StartTime: time.Now(),
		TxID:      c.activeTxID,
	}
	c.emitEvent(ev)
}

func (c *conn) handleParse(m *pgproto.Parse) {
	c.lastParse = m.Query
	if m.Name != "" {
		c.preparedStmts[m.Name] = m.Query
	}
}

func (c *conn) handleBind(m *pgproto.Bind) {
	c.lastBindStmt = m.PreparedStatement
	c.lastBindArgs = make([]string, len(m.Parameters))
	for i, p := range m.Parameters {
		c.lastBindArgs[i] = string(p)
	}
}

func (c *conn) handleExecute() {
	q := c.lastParse
	if c.lastBindStmt != "" {
		if stored, ok := c.preparedStmts[c.lastBindStmt]; ok {
			q = stored
		}
	}

	c.detectTx(q)
	c.executeStart = time.Now()

	ev := proxy.Event{
		ID:        c.generateID(),
		Op:        proxy.OpExecute,
		Query:     q,
		Args:      c.lastBindArgs,
		StartTime: c.executeStart,
		TxID:      c.activeTxID,
	}
	c.emitEvent(ev)
}

func (c *conn) handleCommandComplete(m *pgproto.CommandComplete) {
	rows := parseRowsAffected(string(m.CommandTag))
	_ = rows // rows info is available but we already emitted the event at request time
}

func (c *conn) handleErrorResponse(m *pgproto.ErrorResponse) {
	_ = m // error info is available but we already emitted the event at request time
}

func (c *conn) detectTx(query string) {
	upper := strings.ToUpper(strings.TrimSpace(query))
	switch {
	case strings.HasPrefix(upper, "BEGIN"):
		c.activeTxID = uuid.New().String()
	case strings.HasPrefix(upper, "COMMIT"), strings.HasPrefix(upper, "ROLLBACK"):
		c.activeTxID = ""
	}
}

func (c *conn) emitEvent(ev proxy.Event) {
	select {
	case c.events <- ev:
	default:
		// channel full; drop
	}
}

// parseRowsAffected extracts the row count from a CommandComplete tag.
// e.g. "INSERT 0 5" -> 5, "SELECT 3" -> 3, "UPDATE 10" -> 10.
func parseRowsAffected(tag string) int64 {
	parts := strings.Split(tag, " ")
	if len(parts) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	return n
}

func isClosedErr(err error) bool {
	if err == io.EOF {
		return true
	}
	if netErr, ok := err.(*net.OpError); ok {
		return netErr.Err.Error() == "use of closed network connection"
	}
	return strings.Contains(err.Error(), "closed")
}
