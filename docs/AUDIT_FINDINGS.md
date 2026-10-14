# Quarantine Daemon Audit Findings & Refactor Ledger

Comprehensive audit findings across Performance, Bloat, Spaghetti Architecture, and Code Quality.

## Findings Summary

| ID | Location | Category | Severity | Description | Status |
|---|---|---|---|---|---|
| IPC-01 | `internal/ipc/server.go:311-435` | Spaghetti & Architecture | High | Monolithic 124 LOC `dispatch` routing + error mapping | Resolved |
| PKG-01 | `internal/triage/pkgbuild/rules.go:47-166` | Spaghetti & Architecture | High | Oversized 120 LOC `CheckUntrustedSources` mixing URL/host parsing & trigger synthesis | Resolved |
| BIN-01 | `internal/triage/binary/scorer.go:300-412` | Spaghetti & Architecture | High | Monolithic 113 LOC `TriageBinary` + 68 LOC `calculateCappedScore` | Resolved |
| BIN-02 | `internal/triage/binary/elf.go:84-308` | Spaghetti & Architecture | High | Oversized 109 LOC `parseRawELFHeaders` & 77 LOC `analyzeWithDebugELF` + 439 LOC file | Resolved |

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

---

### [BIN-01] Monolithic `TriageBinary` & `calculateCappedScore` in Binary Scorer

- **File & Location:** `internal/triage/binary/scorer.go:300-412`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  `TriageBinary` spanned 113 LOC, interleaving format dispatch with raw payload entropy calculation, UPX string matching, capability checks, IOC matching, and Go/Rust runtime marker inspection. Additionally, `calculateCappedScore` spanned 68 LOC mixing category summing, cap enforcement, dampener adjustment, and verdict determination.
- **Refactored Code:**
  - Extracted `TriageBinary`, `triageRawPayload`, `detectRawTriggers`, and `detectRuntimeMarkers` into `internal/triage/binary/triage.go` (<50 LOC per function).
  - Decomposed `calculateCappedScore` into `sumCategoryScores` (26 LOC) and `calculateCappedScore` (35 LOC).
  - Modernized `strings.HasPrefix` + `strings.TrimPrefix` to `strings.CutPrefix`.
- **Expected Impact:**
  - `TriageBinary` eliminated as >50 LOC violation.
  - `calculateCappedScore` eliminated as >50 LOC violation.
  - `internal/triage/binary/scorer.go` reduced from 412 LOC to 296 LOC (<=300 LOC limit).
  - Total violations reduced by 3.

---

### [BIN-02] Oversized ELF Parser & Raw Header Analyzer

- **File & Location:** `internal/triage/binary/elf.go:84-308`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  `internal/triage/binary/elf.go` was 439 LOC containing three major violations:
  1. `parseRawELFHeaders` (109 LOC) intermixed 32-bit and 64-bit ELF program header parsing with endianness handling and section table boundary verification.
  2. `analyzeWithDebugELF` (77 LOC) performed program header inspection, .text entropy calculation, section name UPX checks, and multi-table symbol inspection sequentially in one function.
  3. Raw ASCII IOC and IPv4 network candidate extraction logic was bundled directly into `elf.go` despite being used across multiple binary triage routines.
- **Refactored Code:**
  - Extracted raw ELF parsing into `internal/triage/binary/elf_raw.go`: split into `parseRawELFHeaders` (23 LOC), `parseELF32Headers` (31 LOC), `parseELF64Headers` (31 LOC), `processProgHeader` (23 LOC), and `sectionTableInvalid` (7 LOC).
  - Modernized `for` loops using range over integers (`for i := range phnum`).
  - Decomposed `analyzeWithDebugELF` in `elf.go` into targeted inspection helpers (`inspectELFProgramHeaders`, `inspectELFTextSection`, `inspectELFSections`, `inspectELFSymbols`), each <= 18 LOC.
  - Extracted IOC pattern constants, IPv4 candidate parser, and raw IOC scanners to `internal/triage/binary/ioc.go` (116 LOC).
  - Adopted `slices.Contains` in `addCapability` and `addIOC`.
- **Expected Impact:**
  - `parseRawELFHeaders` eliminated as >50 LOC violation.
  - `analyzeWithDebugELF` eliminated as >50 LOC violation.
  - `internal/triage/binary/elf.go` line count dropped from 439 LOC to 210 LOC (<=300 LOC limit).
  - Net metric reduction of 3 violations (27 -> 24).
