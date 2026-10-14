# Quarantine Daemon Audit Findings & Refactor Ledger

Comprehensive audit findings across Performance, Bloat, Spaghetti Architecture, and Code Quality.

## Findings Summary

| ID | Location | Category | Severity | Description | Status |
|---|---|---|---|---|---|
| IPC-01 | `internal/ipc/server.go:311-435` | Spaghetti & Architecture | High | Monolithic 124 LOC `dispatch` routing + error mapping | Resolved |
| PKG-01 | `internal/triage/pkgbuild/rules.go:47-166` | Spaghetti & Architecture | High | Oversized 120 LOC `CheckUntrustedSources` mixing URL/host parsing & trigger synthesis | Resolved |

---

## Detailed Findings

### [IPC-01] Monolithic 124 LOC `dispatch` Routine in IPC Server

- **File & Location:** `internal/ipc/server.go:311-435`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  The `dispatch` method handles all 7 RPC commands in a single 124-line switch block. Parameter validation, vault error mapping (`quarantine.ErrItemNotFound` checks), JSON serialization, and watch path trimming are intermixed inside the dispatch switch, violating the single responsibility principle and exceeding the 50 LOC function threshold.
  ```go
  func (s *Server) dispatch(req *Request) *Response {
      resp := &Response{ID: req.ID}
      switch req.Method {
      case MethodPing: ...
      case MethodGetStatus: ...
      case MethodListVault: ...
      case MethodInspectItem: ...
      case MethodRestoreItem: ...
      case MethodPurgeItem: ...
      case MethodAddWatchPath: ...
      ...
  ```
- **Refactored Code:**
  Extracted modular handlers (`handleGetStatus`, `handleListVault`, `handleInspectItem`, `handleRestoreItem`, `handlePurgeItem`, `handleAddWatchPath`) into `internal/ipc/dispatch.go`. The top-level `dispatch` method is reduced to a concise 22-line routing table.
- **Expected Impact:**
  - `dispatch` reduced from 124 LOC to 22 LOC (<50 LOC limit).
  - `internal/ipc/server.go` line count reduced from 444 LOC to <300 LOC.
  - Decreased coupling and isolated RPC error translation per command.

---

### [PKG-01] Oversized 120 LOC `CheckUntrustedSources` in PKGBUILD Rules

- **File & Location:** `internal/triage/pkgbuild/rules.go:47-166`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  `CheckUntrustedSources` was a 120 LOC function performing raw URL splitting, VCS prefix stripping, URL parsing, hostname normalization, and four separate threat classification checks (IP parsing, shortener matching, pastebin detection, Discord CDN detection) inline within a loop.
- **Refactored Code:**
  Extracted source validation rules into `internal/triage/pkgbuild/sources.go`, decomposing logic into `cleanSourceURL` (16 LOC), `classifyUntrustedHost` (34 LOC), and a streamlined `CheckUntrustedSources` (39 LOC), while adopting `strings.CutPrefix`.
- **Expected Impact:**
  - `CheckUntrustedSources` reduced from 120 LOC to 39 LOC (<50 LOC limit).
  - `internal/triage/pkgbuild/rules.go` reduced from 767 LOC to 597 LOC.
  - Eliminated network/URL dependencies from `rules.go`.
