# Quarantine Daemon Audit Findings & Refactor Ledger

Comprehensive audit findings across Performance, Bloat, Spaghetti Architecture, and Code Quality.

## Findings Summary

| ID | Location | Category | Severity | Description | Status |
|---|---|---|---|---|---|
| IPC-01 | `internal/ipc/server.go:311-435` | Spaghetti & Architecture | High | Monolithic 124 LOC `dispatch` routing + error mapping | Resolved |
| PKG-01 | `internal/triage/pkgbuild/rules.go:47-166` | Spaghetti & Architecture | High | Oversized 120 LOC `CheckUntrustedSources` mixing URL/host parsing & trigger synthesis | Resolved |
| BIN-01 | `internal/triage/binary/scorer.go:300-412` | Spaghetti & Architecture | High | Monolithic 113 LOC `TriageBinary` + 68 LOC `calculateCappedScore` | Resolved |
| BIN-02 | `internal/triage/binary/elf.go:84-308` | Spaghetti & Architecture | High | Oversized 109 LOC `parseRawELFHeaders` & 77 LOC `analyzeWithDebugELF` + 439 LOC file | Resolved |
| QUA-01 | `internal/quarantine/vault.go:124-500` | Spaghetti & Architecture | High | 628 LOC file + 101 LOC `QuarantineFile`, 117 LOC `Restore`, 56 LOC `Sweep` | Resolved |
| TUI-01 | `internal/tui/model.go:390-666` | Spaghetti & Architecture | High | 842 LOC file + 115 LOC `update`, 97 LOC `handleKey` | Resolved |
| TUI-02 | `internal/tui/view.go:207-670` | Spaghetti & Architecture | High | 729 LOC file + 67 LOC `renderWatchPane` | Resolved |

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

---

### [QUA-01] Monolithic Quarantine Vault Operations & Lifecycle Routines

- **File & Location:** `internal/quarantine/vault.go:124-500`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  `internal/quarantine/vault.go` was 628 LOC, combining vault coordination with:
  1. `QuarantineFile` (101 LOC): source hashing, inode resolution, move coordination, permission neutralization, PKGBUILD decoy stub generation, and metadata sidecar writing.
  2. `Restore` (117 LOC): destination validation, PKGBUILD decoy stub verification, temporary file staging, permission elevation/neutralization, hard link/rename publishing, and artifact cleanup.
  3. `Sweep` (56 LOC): dual-pass directory traversal across active sidecars and orphaned raw payload files.
  4. Item metadata JSON serialization, atomic file writing, and PKGBUILD stub constants.
- **Refactored Code:**
  - Extracted metadata structures and sidecar lifecycle into `internal/quarantine/meta.go` (128 LOC).
  - Extracted `QuarantineFile` into `internal/quarantine/quarantine.go` (137 LOC), decomposing into `readSourceInfo`, `commitQuarantine`, and `finalizeQuarantine` (all <= 32 LOC).
  - Extracted `Restore` into `internal/quarantine/restore.go` (164 LOC), decomposing into `checkRestoreDestination`, `stageRestoreArtifact`, `copyArtifactContent`, `publishRestoredFile`, and `cleanupRestoredVaultItem` (all <= 38 LOC).
  - Decomposed `Sweep` in `vault.go` into `sweepManaged` and `sweepOrphans` (all <= 21 LOC).
- **Expected Impact:**
  - `QuarantineFile` eliminated as >50 LOC violation.
  - `Restore` eliminated as >50 LOC violation.
  - `Sweep` eliminated as >50 LOC violation.
  - `internal/quarantine/vault.go` line count dropped from 628 LOC to 296 LOC (<=300 LOC limit).
  - Net metric reduction of 4 violations (24 -> 20).

---

### [TUI-01] Oversized Model Lifecycle, Event Dispatch & Key Handling in TUI

- **File & Location:** `internal/tui/model.go:390-666`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  `internal/tui/model.go` was 842 LOC, combining Bubble Tea model state with:
  1. `update` (115 LOC): massive type switch handling all Bubble Tea messages (`tickMsg`, `connectMsg`, `statusMsg`, `vaultMsg`, `inspectMsg`, `actionMsg`, `addWatchMsg`, `spinner.TickMsg`) directly inside the central update loop.
  2. `handleKey` (97 LOC): monolithic keyboard input handling coordinating input buffer typing, confirmation dialogs, global navigation shortcuts, watch preset navigation, vault scrolling, and item actions in a single cascading condition block.
  3. IPC Client commands and Dialers (`refreshCmd`, `connectCmd`, `statusOnlyCmd`, `vaultOnlyCmd`, `fetchCmd`, `inspectCmd`, `actionCmd`, `addWatchCmd`) intermixed with UI model logic.
- **Refactored Code:**
  - Extracted IPC Client interface, dialers, IPC commands, and connection error handling into `internal/tui/commands.go` (224 LOC).
  - Extracted key handling, cursor navigation, and window clamping into `internal/tui/handlers.go` (258 LOC), decomposing `handleKey` into modular handlers (`handleGlobalKey`, `handleWatchKey`, `handleVaultKey`, `handleActionKey`, `handleConfirmKey`, `handleInputKey`), all <= 28 LOC. Modernized bounds clamping with Go `max()`.
  - Extracted asynchronous message reaction routines into `internal/tui/messages.go` (166 LOC), reducing `update` in `model.go` to a concise 26 LOC dispatcher.
  - Reduced `internal/tui/model.go` from 842 LOC to 227 LOC (<=300 LOC limit).
- **Expected Impact:**
  - `update` eliminated as >50 LOC violation.
  - `handleKey` eliminated as >50 LOC violation.
  - `internal/tui/model.go` line count dropped from 842 LOC to 227 LOC (<=300 LOC limit).
  - Net metric reduction of 3 violations (20 -> 17).

---

### [TUI-02] Oversized View Rendering, Pane Layout & Watch Target View

- **File & Location:** `internal/tui/view.go:207-670`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  `internal/tui/view.go` was 729 LOC combining central terminal chrome layout, adaptive lipgloss theme definitions, confirmation modals, dashboard rendering, vault table rendering with columnar cell formatting, inspector metadata display, watch target presets with dynamic active status badges, and 67 LOC `renderWatchPane`.
- **Refactored Code:**
  - Extracted dashboard, vault table, inspector metadata display, and connection offline frames into `internal/tui/view_panes.go` (268 LOC).
  - Extracted watch targets preset table and directory monitor guide into `internal/tui/view_watch.go` (100 LOC), decomposing `renderWatchPane` from 67 LOC into modular subroutines (`renderWatchActive`, `renderWatchPresets`, `renderWatchGuide`), each <= 27 LOC.
  - Extracted path truncation, cell alignment, uptime formatting, and line clamping into `internal/tui/view_layout.go` (103 LOC).
  - Reduced `internal/tui/view.go` from 729 LOC to 293 LOC (<= 300 LOC limit).
- **Expected Impact:**
  - `renderWatchPane` eliminated as >50 LOC violation.
  - `internal/tui/view.go` line count dropped from 729 LOC to 293 LOC (<= 300 LOC limit).
  - Net metric reduction of 2 violations (17 -> 15).
