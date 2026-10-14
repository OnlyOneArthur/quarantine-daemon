package ipc

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestMutationReturnsOriginalTransportError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	c := &Client{socketPath: "/nonexistent/quarantined.sock", conn: clientConn, rd: bufio.NewReader(clientConn)}
	defer c.Close()
	go func() {
		_, _ = bufio.NewReader(serverConn).ReadBytes(byte('\n'))
		_ = serverConn.Close() // request processed; response lost
	}()
	err := c.call(context.Background(), MethodPurgeItem, ItemParams{ID: "example"}, nil)
	if err == nil || !strings.Contains(err.Error(), "read response:") {
		t.Fatalf("got %v, want original lost-response error, not a redial error", err)
	}
}

func TestCancelWithoutDeadlineInterruptsExchange(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	c := &Client{conn: clientConn, rd: bufio.NewReader(clientConn)}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requestRead := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(serverConn).ReadBytes(byte('\n'))
		close(requestRead)
	}()
	done := make(chan error, 1)
	go func() { done <- c.call(ctx, MethodPurgeItem, ItemParams{ID: "example"}, nil) }()
	select {
	case <-requestRead:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach peer")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt blocked read")
	}
}

// TestMismatchedResponseIDIsRejected ensures a response whose id does not match
// the request is treated as a transport failure and drops the connection.
func TestMismatchedResponseIDIsRejected(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	c := &Client{conn: client, rd: bufio.NewReader(client)}
	defer c.Close()
	// Reply with a valid-looking response carrying the wrong id.
	go func() {
		buf := make([]byte, 512)
		n, _ := server.Read(buf)
		_ = n
		_, _ = server.Write([]byte(`{"id":"bogus","result":{}}` + "\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out map[string]any
	err := c.call(ctx, MethodPing, nil, &out)
	if err == nil || !strings.Contains(err.Error(), "does not match request id") {
		t.Fatalf("call error = %v, want response-id mismatch", err)
	}
	if c.conn != nil {
		t.Fatal("connection should be dropped after a mismatched response id")
	}
}
