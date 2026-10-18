package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
)

// DefaultDialTimeout bounds how long NewClient waits for the daemon to accept.
const DefaultDialTimeout = 2 * time.Second

// Client is a concurrency-safe JSON-RPC client for the daemon control socket.
type Client struct {
	socketPath string
	timeout    time.Duration

	mu   sync.Mutex
	conn net.Conn
	rd   *bufio.Reader
	seq  uint64
}

// NewClient connects to the daemon listening on socketPath.
func NewClient(socketPath string) (*Client, error) {
	c := &Client{
		socketPath: socketPath,
		timeout:    DefaultDialTimeout,
	}
	if err := c.dial(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) dial() error {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return fmt.Errorf("dial unix socket %s: %w", c.socketPath, err)
	}
	c.conn = conn
	c.rd = bufio.NewReader(conn)
	return nil
}

// Close terminates the underlying connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	c.rd = nil
	return err
}

// call sends a request and decodes the response. If the connection is broken
// during the exchange it redials; idempotent methods are then resent once, while
// mutating methods return the transport error so a lost response cannot cause a
// second mutation.
func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	req, payload, err := c.prepareRequest(method, params)
	if err != nil {
		return err
	}

	line, err := c.executeExchange(ctx, method, payload)
	if err != nil {
		return err
	}

	return c.decodeResponse(line, req.ID, out)
}

func (c *Client) prepareRequest(method string, params any) (*Request, []byte, error) {
	req := &Request{Method: method}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal params: %w", err)
		}
		req.Params = raw
	}
	c.seq++
	req.ID = fmt.Sprintf("%d", c.seq)

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal request: %w", err)
	}
	return req, append(payload, '\n'), nil
}

func (c *Client) executeExchange(ctx context.Context, method string, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.conn == nil {
		if err := c.dial(); err != nil {
			return nil, err
		}
	}
	line, err := c.exchange(ctx, payload)
	if err != nil {
		if !isIdempotent(method) || ctx.Err() != nil {
			return nil, err
		}
		if dialErr := c.dial(); dialErr != nil {
			return nil, dialErr
		}
		return c.exchange(ctx, payload)
	}
	return line, nil
}

func (c *Client) decodeResponse(line []byte, reqID string, out any) error {
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		c.drop()
		return fmt.Errorf("decode response: %w", err)
	}
	if resp.ID != reqID {
		// A synchronous client only ever has one request in flight, so a
		// mismatched id means the stream is desynchronized (or corrupted).
		// Drop the connection and surface it as a transport error so an
		// idempotent call can redial and retry cleanly.
		c.drop()
		return fmt.Errorf("response id %q does not match request id %q", resp.ID, reqID)
	}
	if resp.Error != nil {
		return resp.Error
	}
	if out != nil {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("decode result: %w", err)
		}
	}
	return nil
}

// isIdempotent reports whether method is safe to resend after a transport failure.
// AddWatchPath is a mutation, but the server deduplicates its normalized path.
func isIdempotent(method string) bool {
	switch method {
	case MethodPing, MethodGetStatus, MethodListVault, MethodInspectItem, MethodAddWatchPath:
		return true
	default:
		return false
	}
}

// exchange writes payload and reads one response line. Caller must hold c.mu.
// On transport failure the connection is dropped so the caller can redial.
func (c *Client) exchange(ctx context.Context, payload []byte) ([]byte, error) {
	if c.conn == nil {
		return nil, errors.New("not connected")
	}
	if err := ctx.Err(); err != nil {
		c.drop()
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(deadline)
	} else {
		_ = c.conn.SetDeadline(time.Time{})
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func(conn net.Conn) {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}(c.conn)
	defer func() { close(done); <-stopped }()
	if _, err := c.conn.Write(payload); err != nil {
		c.drop()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("write request: %w", err)
	}
	line, err := c.rd.ReadBytes('\n')
	if err != nil {
		c.drop()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("read response: %w", err)
	}
	return line, nil
}

// drop closes the current connection. Caller must hold c.mu.
func (c *Client) drop() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = nil
	c.rd = nil
}

// Ping verifies connectivity and that the server is responsive.
func (c *Client) Ping(ctx context.Context) error {
	return c.call(ctx, MethodPing, nil, nil)
}

// GetStatus fetches the daemon status snapshot.
func (c *Client) GetStatus(ctx context.Context) (*StatusResponse, error) {
	var out StatusResponse
	if err := c.call(ctx, MethodGetStatus, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListVault returns metadata for every quarantined item.
func (c *Client) ListVault(ctx context.Context) ([]*quarantine.ItemMetadata, error) {
	var out []*quarantine.ItemMetadata
	if err := c.call(ctx, MethodListVault, nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []*quarantine.ItemMetadata{}
	}
	return out, nil
}

// InspectItem returns metadata for a single quarantined item by id.
func (c *Client) InspectItem(ctx context.Context, id string) (*quarantine.ItemMetadata, error) {
	var out quarantine.ItemMetadata
	if err := c.call(ctx, MethodInspectItem, ItemParams{ID: id}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RestoreItem restores a quarantined item to its original path, or to destPath when non-empty.
func (c *Client) RestoreItem(ctx context.Context, id, destPath string) error {
	return c.call(ctx, MethodRestoreItem, ItemParams{ID: id, DestPath: destPath}, nil)
}

// PurgeItem permanently deletes a quarantined item and its sidecar.
func (c *Client) PurgeItem(ctx context.Context, id string) error {
	return c.call(ctx, MethodPurgeItem, ItemParams{ID: id}, nil)
}

// AddWatchPath instructs the daemon to watch an additional file or directory path.
func (c *Client) AddWatchPath(ctx context.Context, path string) error {
	return c.call(ctx, MethodAddWatchPath, AddWatchPathParams{Path: path}, nil)
}
