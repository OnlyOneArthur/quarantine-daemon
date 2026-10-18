package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/quarantine"
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
	if err := json.Unmarshal(req.Params, &p); err != nil || p.ID == "" || strings.ContainsAny(p.ID, "/\\") || strings.Contains(p.ID, "..") {
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
		s.handleGetStatus(resp)
	case MethodListVault:
		s.handleListVault(resp)
	case MethodInspectItem:
		s.handleInspectItem(req, resp)
	case MethodRestoreItem:
		s.handleRestoreItem(req, resp)
	case MethodPurgeItem:
		s.handlePurgeItem(req, resp)
	case MethodAddWatchPath:
		s.handleAddWatchPath(req, resp)
	default:
		resp.Error = &RPCError{Code: "METHOD_NOT_FOUND", Message: fmt.Sprintf("unknown method: %s", req.Method)}
	}

	return resp
}

func (s *Server) handleGetStatus(resp *Response) {
	var st StatusResponse
	if s.provider != nil {
		st = s.provider.Status()
	}
	data, err := json.Marshal(st)
	if err != nil {
		resp.Error = &RPCError{Code: "INTERNAL_ERROR", Message: err.Error()}
		return
	}
	resp.Result = data
}

func (s *Server) handleListVault(resp *Response) {
	v := s.vaultOrError(resp)
	if v == nil {
		return
	}
	items, err := v.List()
	if err != nil {
		resp.Error = &RPCError{Code: "VAULT_ERROR", Message: err.Error()}
		return
	}
	data, err := json.Marshal(items)
	if err != nil {
		resp.Error = &RPCError{Code: "INTERNAL_ERROR", Message: err.Error()}
		return
	}
	resp.Result = data
}

func (s *Server) handleInspectItem(req *Request, resp *Response) {
	v := s.vaultOrError(resp)
	if v == nil {
		return
	}
	p, ok := decodeItemParams(req, resp)
	if !ok {
		return
	}
	meta, err := v.Inspect(p.ID)
	if err != nil {
		if errors.Is(err, quarantine.ErrItemNotFound) {
			resp.Error = &RPCError{Code: "ITEM_NOT_FOUND", Message: err.Error()}
		} else {
			resp.Error = &RPCError{Code: "VAULT_ERROR", Message: err.Error()}
		}
		return
	}
	data, err := json.Marshal(meta)
	if err != nil {
		resp.Error = &RPCError{Code: "INTERNAL_ERROR", Message: err.Error()}
		return
	}
	resp.Result = data
}

func (s *Server) handleRestoreItem(req *Request, resp *Response) {
	v := s.vaultOrError(resp)
	if v == nil {
		return
	}
	p, ok := decodeItemParams(req, resp)
	if !ok {
		return
	}
	if err := v.Restore(p.ID, p.DestPath); err != nil {
		if errors.Is(err, quarantine.ErrItemNotFound) {
			resp.Error = &RPCError{Code: "ITEM_NOT_FOUND", Message: err.Error()}
		} else {
			resp.Error = &RPCError{Code: "RESTORE_ERROR", Message: err.Error()}
		}
		return
	}
	resp.Result = json.RawMessage(`{"status":"ok"}`)
}

func (s *Server) handlePurgeItem(req *Request, resp *Response) {
	v := s.vaultOrError(resp)
	if v == nil {
		return
	}
	p, ok := decodeItemParams(req, resp)
	if !ok {
		return
	}
	if err := v.Purge(p.ID); err != nil {
		if errors.Is(err, quarantine.ErrItemNotFound) {
			resp.Error = &RPCError{Code: "ITEM_NOT_FOUND", Message: err.Error()}
		} else {
			resp.Error = &RPCError{Code: "PURGE_ERROR", Message: err.Error()}
		}
		return
	}
	resp.Result = json.RawMessage(`{"status":"ok"}`)
}

func (s *Server) handleAddWatchPath(req *Request, resp *Response) {
	s.mu.Lock()
	wm := s.watchManager
	s.mu.Unlock()
	if wm == nil {
		resp.Error = &RPCError{Code: "WATCHER_UNAVAILABLE", Message: "watcher management is not configured"}
		return
	}
	var p AddWatchPathParams
	if err := json.Unmarshal(req.Params, &p); err != nil || strings.TrimSpace(p.Path) == "" {
		resp.Error = &RPCError{Code: "INVALID_PARAMS", Message: "missing or empty path parameter"}
		return
	}
	if err := wm.AddWatchPath(strings.TrimSpace(p.Path)); err != nil {
		resp.Error = &RPCError{Code: "WATCH_ERROR", Message: err.Error()}
		return
	}
	resp.Result = json.RawMessage(`{"status":"ok"}`)
}
