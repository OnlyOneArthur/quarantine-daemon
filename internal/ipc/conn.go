package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// Connection deadlines bound a single misbehaving client: without them a
// stalled peer would pin a handler goroutine and its file descriptor forever.
const (
	connReadTimeout  = 5 * time.Minute
	connWriteTimeout = 30 * time.Second
)

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

func (s *Server) authenticateConn(conn net.Conn) error {
	clientUID, err := peerCred(conn)
	if err != nil {
		s.writeError(conn, "", "AUTH_ERROR", err.Error())
		return err
	}
	if clientUID != uint32(os.Getuid()) {
		s.writeError(conn, "", "UNAUTHORIZED", ErrUnauthorized.Error())
		return ErrUnauthorized
	}
	return nil
}

func (s *Server) processRequest(conn net.Conn, line []byte) bool {
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		s.writeError(conn, "", "INVALID_REQUEST", fmt.Sprintf("invalid JSON payload: %v", err))
		return false
	}

	resp := s.dispatch(&req)
	data, err := json.Marshal(resp)
	if err != nil {
		s.writeError(conn, req.ID, "INTERNAL_ERROR", "failed to marshal response")
		return false
	}
	data = append(data, '\n')
	_ = conn.SetWriteDeadline(time.Now().Add(connWriteTimeout))
	_, writeErr := conn.Write(data)
	return writeErr == nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		s.untrackConn(conn)
		_ = conn.Close()
		s.wg.Done()
	}()

	if err := s.authenticateConn(conn); err != nil {
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
		if !s.processRequest(conn, line) {
			return
		}
	}

	// EOF and closed connections end the scan with a nil error; an idle timeout
	// is a normal hang-up, while anything else (e.g. a line over the buffer
	// limit) is reported to the client.
	if err := scanner.Err(); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.writeError(conn, "", "INVALID_REQUEST", err.Error())
	}
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
