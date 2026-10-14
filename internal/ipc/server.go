package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
)

var (
	// ErrServerAlreadyRunning is returned when a live daemon is already listening on the socket.
	ErrServerAlreadyRunning = errors.New("daemon is already running on socket")
	// ErrUnauthorized is returned when client peer credentials do not match daemon UID.
	ErrUnauthorized = errors.New("unauthorized: client UID does not match daemon UID")
)

// StatusProvider exposes the status information reported via GetStatus.
type StatusProvider interface {
	Status() StatusResponse
}

// WatchManager exposes dynamic watch path registration.
type WatchManager interface {
	AddWatchPath(path string) error
}

// StaticStatusProvider provides static status information for testing or simple setups.
type StaticStatusProvider struct {
	StatusData StatusResponse
}

// Status returns the fixed status payload this provider was built with.
func (s StaticStatusProvider) Status() StatusResponse {
	return s.StatusData
}

// Server is a Unix domain socket server handling IPC requests.
type Server struct {
	socketPath   string
	vault        *quarantine.Vault
	provider     StatusProvider
	watchManager WatchManager

	ln       net.Listener
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	closed   bool
	stopOnce sync.Once

	// stopped is closed by Stop so the context-watcher goroutine can exit even
	// when the caller never cancels the context.
	stopped chan struct{}
}

// NewServer returns an unstarted Server configured to listen at socketPath.
func NewServer(socketPath string, vault *quarantine.Vault, statusProvider StatusProvider) *Server {
	return &Server{
		socketPath: filepath.Clean(socketPath),
		vault:      vault,
		provider:   statusProvider,
		conns:      make(map[net.Conn]struct{}),
		stopped:    make(chan struct{}),
	}
}

// SetWatchManager attaches a WatchManager to the server.
func (s *Server) SetWatchManager(wm WatchManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.watchManager = wm
}

// Start recovers any stale socket, creates the Unix domain socket listener,
// secures file permissions to 0600, and begins accepting connections until ctx is cancelled
// or Stop is called.
func (s *Server) Start(ctx context.Context) error {
	if err := s.prepareSocket(); err != nil {
		return err
	}

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}

	// Restrict permissions to owner-only: 0600
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		_ = ln.Close()
		_ = os.Remove(s.socketPath)
		return fmt.Errorf("chmod socket 0600: %w", err)
	}

	// Stop may have run while Listen was in progress; in that case it saw no
	// listener and removed the socket path, so release what we just created.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		_ = os.Remove(s.socketPath)
		return net.ErrClosed
	}
	s.ln = ln
	s.wg.Add(1)
	s.mu.Unlock()

	// Shutdown asynchronously if context is cancelled. Select on stopped so the
	// goroutine cannot outlive a direct Stop call that left the context live.
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Stop()
		case <-s.stopped:
		}
	}()

	defer s.wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}

		if !s.trackConn(conn) {
			continue
		}
		go s.handleConn(conn)
	}
}

// prepareSocket implements stale socket detection and cleanup:
// If the socket file exists, attempts DialTimeout(200ms).
// If dial succeeds, ErrServerAlreadyRunning is returned.
// If dial fails, stale file is removed before listening.
func (s *Server) prepareSocket() error {
	if _, err := os.Lstat(s.socketPath); err != nil {
		if os.IsNotExist(err) {
			// Ensure parent directory exists
			dir := filepath.Dir(s.socketPath)
			if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
				return fmt.Errorf("create socket parent dir: %w", mkErr)
			}
			return nil
		}
		return fmt.Errorf("stat socket path: %w", err)
	}

	// Socket file exists: probe if a daemon is running.
	conn, err := net.DialTimeout("unix", s.socketPath, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return ErrServerAlreadyRunning
	}

	// Connection refused or dial error -> stale socket. Clean it up.
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	return nil
}

// Stop closes the listener, aborts active connections, and cleans up the socket file.
func (s *Server) Stop() error {
	var stopErr error
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		ln := s.ln
		s.ln = nil
		conns := make([]net.Conn, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.mu.Unlock()

		close(s.stopped)

		if ln != nil {
			if err := ln.Close(); err != nil {
				stopErr = err
			}
		}

		for _, c := range conns {
			_ = c.Close()
		}

		// Wait for the accept loop and every in-flight handler to unwind so
		// Stop returns only after all connection goroutines have exited.
		s.wg.Wait()

		// Remove socket file
		if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
			if stopErr == nil {
				stopErr = err
			}
		}
	})
	return stopErr
}

func (s *Server) trackConn(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *Server) untrackConn(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		s.untrackConn(conn)
		_ = conn.Close()
		s.wg.Done()
	}()

	// SO_PEERCRED check: caller must match current UID
	clientUID, err := peerCred(conn)
	if err != nil {
		s.writeError(conn, "", "AUTH_ERROR", err.Error())
		return
	}
	if clientUID != uint32(os.Getuid()) {
		s.writeError(conn, "", "UNAUTHORIZED", ErrUnauthorized.Error())
		return
	}

	scanner := bufio.NewScanner(conn)
	// Support messages up to 10MB (for large vault item listings)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(connReadTimeout))
		if !scanner.Scan() {
			break
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.writeError(conn, "", "INVALID_REQUEST", fmt.Sprintf("invalid JSON payload: %v", err))
			return
		}

		resp := s.dispatch(&req)
		data, err := json.Marshal(resp)
		if err != nil {
			s.writeError(conn, req.ID, "INTERNAL_ERROR", "failed to marshal response")
			return
		}
		data = append(data, '\n')
		_ = conn.SetWriteDeadline(time.Now().Add(connWriteTimeout))
		if _, err := conn.Write(data); err != nil {
			return
		}
	}

	// EOF and closed connections end the scan with a nil error; an idle timeout
	// is a normal hang-up, while anything else (e.g. a line over the buffer
	// limit) is reported to the client.
	if err := scanner.Err(); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
		s.writeError(conn, "", "INVALID_REQUEST", err.Error())
	}
}

// Connection deadlines bound a single misbehaving client: without them a
// stalled peer would pin a handler goroutine and its file descriptor forever.
const (
	connReadTimeout  = 5 * time.Minute
	connWriteTimeout = 30 * time.Second
)

// vaultOrError returns the configured vault, or records VAULT_UNAVAILABLE on resp.
func (s *Server) vaultOrError(resp *Response) *quarantine.Vault {
	if s.vault == nil {
		resp.Error = &RPCError{Code: "VAULT_UNAVAILABLE", Message: "quarantine vault is not configured"}
		return nil
	}
	return s.vault
}

// decodeItemParams decodes an ItemParams payload, or records INVALID_PARAMS on resp.
func decodeItemParams(req *Request, resp *Response) (ItemParams, bool) {
	var p ItemParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.ID == "" {
		resp.Error = &RPCError{Code: "INVALID_PARAMS", Message: "missing or invalid id parameter"}
		return p, false
	}
	return p, true
}

func (s *Server) dispatch(req *Request) *Response {
	resp := &Response{ID: req.ID}

	switch req.Method {
	case MethodPing:
		resp.Result = json.RawMessage(`{"status":"ok"}`)

	case MethodGetStatus:
		var st StatusResponse
		if s.provider != nil {
			st = s.provider.Status()
		}
		data, err := json.Marshal(st)
		if err != nil {
			resp.Error = &RPCError{Code: "INTERNAL_ERROR", Message: err.Error()}
			return resp
		}
		resp.Result = data

	case MethodListVault:
		v := s.vaultOrError(resp)
		if v == nil {
			return resp
		}
		items, err := v.List()
		if err != nil {
			resp.Error = &RPCError{Code: "VAULT_ERROR", Message: err.Error()}
			return resp
		}
		data, err := json.Marshal(items)
		if err != nil {
			resp.Error = &RPCError{Code: "INTERNAL_ERROR", Message: err.Error()}
			return resp
		}
		resp.Result = data

	case MethodInspectItem:
		v := s.vaultOrError(resp)
		if v == nil {
			return resp
		}
		p, ok := decodeItemParams(req, resp)
		if !ok {
			return resp
		}
		meta, err := v.Inspect(p.ID)
		if err != nil {
			if errors.Is(err, quarantine.ErrItemNotFound) {
				resp.Error = &RPCError{Code: "ITEM_NOT_FOUND", Message: err.Error()}
			} else {
				resp.Error = &RPCError{Code: "VAULT_ERROR", Message: err.Error()}
			}
			return resp
		}
		data, err := json.Marshal(meta)
		if err != nil {
			resp.Error = &RPCError{Code: "INTERNAL_ERROR", Message: err.Error()}
			return resp
		}
		resp.Result = data

	case MethodRestoreItem:
		v := s.vaultOrError(resp)
		if v == nil {
			return resp
		}
		p, ok := decodeItemParams(req, resp)
		if !ok {
			return resp
		}
		if err := v.Restore(p.ID, p.DestPath); err != nil {
			if errors.Is(err, quarantine.ErrItemNotFound) {
				resp.Error = &RPCError{Code: "ITEM_NOT_FOUND", Message: err.Error()}
			} else {
				resp.Error = &RPCError{Code: "RESTORE_ERROR", Message: err.Error()}
			}
			return resp
		}
		resp.Result = json.RawMessage(`{"status":"ok"}`)

	case MethodPurgeItem:
		v := s.vaultOrError(resp)
		if v == nil {
			return resp
		}
		p, ok := decodeItemParams(req, resp)
		if !ok {
			return resp
		}
		if err := v.Purge(p.ID); err != nil {
			if errors.Is(err, quarantine.ErrItemNotFound) {
				resp.Error = &RPCError{Code: "ITEM_NOT_FOUND", Message: err.Error()}
			} else {
				resp.Error = &RPCError{Code: "PURGE_ERROR", Message: err.Error()}
			}
			return resp
		}
		resp.Result = json.RawMessage(`{"status":"ok"}`)

	case MethodAddWatchPath:
		s.mu.Lock()
		wm := s.watchManager
		s.mu.Unlock()
		if wm == nil {
			resp.Error = &RPCError{Code: "WATCHER_UNAVAILABLE", Message: "watcher management is not configured"}
			return resp
		}
		var p AddWatchPathParams
		if err := json.Unmarshal(req.Params, &p); err != nil || strings.TrimSpace(p.Path) == "" {
			resp.Error = &RPCError{Code: "INVALID_PARAMS", Message: "missing or empty path parameter"}
			return resp
		}
		if err := wm.AddWatchPath(strings.TrimSpace(p.Path)); err != nil {
			resp.Error = &RPCError{Code: "WATCH_ERROR", Message: err.Error()}
			return resp
		}
		resp.Result = json.RawMessage(`{"status":"ok"}`)

	default:
		resp.Error = &RPCError{Code: "METHOD_NOT_FOUND", Message: fmt.Sprintf("unknown method: %s", req.Method)}
	}

	return resp
}

func (s *Server) writeError(w io.Writer, id, code, msg string) {
	resp := Response{
		ID:    id,
		Error: &RPCError{Code: code, Message: msg},
	}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = w.Write(data)
}
