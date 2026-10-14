package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

	ln, err := s.createListener()
	if err != nil {
		return err
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
	return s.acceptLoop(ln)
}

func (s *Server) createListener() (net.Listener, error) {
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}

	if err := os.Chmod(s.socketPath, 0600); err != nil {
		_ = ln.Close()
		_ = os.Remove(s.socketPath)
		return nil, fmt.Errorf("chmod socket 0600: %w", err)
	}
	return ln, nil
}

func (s *Server) acceptLoop(ln net.Listener) error {
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
			dir := filepath.Dir(s.socketPath)
			if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
				return fmt.Errorf("create socket parent dir: %w", mkErr)
			}
			return nil
		}
		return fmt.Errorf("stat socket path: %w", err)
	}

	conn, err := net.DialTimeout("unix", s.socketPath, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return ErrServerAlreadyRunning
	}

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

		if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
			if stopErr == nil {
				stopErr = err
			}
		}
	})
	return stopErr
}
