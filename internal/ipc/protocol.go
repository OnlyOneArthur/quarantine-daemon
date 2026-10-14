// Package ipc implements the quarantined daemon's control-plane RPC over a
// Unix domain socket using newline-delimited JSON messages, authenticated via
// SO_PEERCRED so only the daemon's own UID may connect.
package ipc

import (
	"encoding/json"
)

// Method names understood by the server.
const (
	MethodPing         = "Ping"
	MethodGetStatus    = "GetStatus"
	MethodListVault    = "ListVault"
	MethodInspectItem  = "InspectItem"
	MethodRestoreItem  = "RestoreItem"
	MethodPurgeItem    = "PurgeItem"
	MethodAddWatchPath = "AddWatchPath"
)

// Request is a single newline-delimited JSON RPC request.
type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is a single newline-delimited JSON RPC response. Exactly one of
// Result or Error is populated.
type Response struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

// RPCError is a structured protocol-level error returned by the server.
type RPCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	return e.Code + ": " + e.Message
}

// ItemParams are the parameters for InspectItem, RestoreItem and PurgeItem.
type ItemParams struct {
	ID string `json:"id"`
	// DestPath optionally overrides the restore destination for RestoreItem.
	DestPath string `json:"dest_path,omitempty"`
}

// AddWatchPathParams are the parameters for AddWatchPath.
type AddWatchPathParams struct {
	Path string `json:"path"`
}

// StatusResponse is the payload for GetStatus.
type StatusResponse struct {
	Uptime          float64  `json:"uptime_seconds"` // daemon uptime in seconds
	Version         string   `json:"version"`
	ScannedCount    int64    `json:"scanned_count"`
	QuarantineCount int64    `json:"quarantine_count"`
	WatchPaths      []string `json:"watch_paths"`

	// ThresholdScore and AlertScore let the TUI label scores with the same
	// verdict boundaries the daemon actually applies, instead of guessing.
	ThresholdScore int `json:"threshold_score"`
	AlertScore     int `json:"alert_score"`
}
