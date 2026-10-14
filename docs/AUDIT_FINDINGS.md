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
| PKG-02 | `internal/triage/pkgbuild/rules.go:96-594` | Spaghetti & Architecture | High | 594 LOC file + 70 LOC `checkCallExpr`, 55 LOC `checkTamperingCommand`, 51 LOC `cmdSubstOutputExecuted` | Resolved |
| WAT-01 | `internal/watcher/watcher.go:1-565` | Spaghetti & Architecture | High | 565 LOC file mixing monitoring, debouncing, file readiness polling, and reconcile walks | Resolved |
| PKG-03 | `internal/triage/pkgbuild/scorer.go:13-95` | Spaghetti & Architecture | Medium | 82 LOC `ScorePKGBUILD` mixing trigger collection, score/verdict calculation & dampener deduplication | Resolved |
| PKG-04 | `internal/triage/pkgbuild/dampeners.go:35-107` | Spaghetti & Architecture | Medium | 71 LOC `EvaluateIntegrity` intermixing VCS exemptions, missing checksum checks & inline SKIP closures | Resolved |
| BIN-03 | `internal/triage/binary/detector.go:22-87` | Spaghetti & Architecture | Medium | 65 LOC `DetectFormat` intermixing script shebang, ELF, Mach-O universal, and PE header parsing | Resolved |
| BIN-04 | `internal/triage/binary/pe.go:19-78` | Spaghetti & Architecture | Medium | 69 LOC `AnalyzePE` mixing section characteristic analysis, import inspection, and raw capability scans | Resolved |
| IPC-02 | `internal/ipc/client.go:69-134` | Spaghetti & Architecture | Medium | 65 LOC `call` intermixing request preparation, redial/retry exchanges, and response parsing | Resolved |
| IPC-03 | `internal/ipc/server.go:76-299` | Spaghetti & Architecture | High | 61 LOC `handleConn` + 59 LOC `Start` + connection pooling and lifecycle intermixed in `server.go` | Resolved |
| QUA-02 | `internal/quarantine/move_posix.go:57-114` | Spaghetti & Architecture | Medium | 58 LOC `crossDeviceCopy` mixing safe file reading, staging, fsync, rename, inode verification, and unlinking | Resolved |
| PKG-05 | `internal/triage/pkgbuild/parser.go:197-251` | Spaghetti & Architecture | Low | 55 LOC `WalkScopeAncestors` intermixing install scriptlet AST traversal and PKGBUILD function-depth scope tracking | Resolved |
| CMD-01 | `cmd/quarantined/main.go:92-174` | Spaghetti & Architecture | High | 83 LOC `run` intermixing signal trap, vault setup, inotify watcher, pipeline wiring, IPC launch, hourly ticker, event loop, and shutdown | Resolved |

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

---

### [PKG-02] Oversized AST Rule Engine, Path Tampering & Network Execution Handlers

- **File & Location:** `internal/triage/pkgbuild/rules.go:96-594`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  `internal/triage/pkgbuild/rules.go` was 594 LOC combining core AST traversal with:
  1. `checkCallExpr` (70 LOC): handling `eval`, `base64` decode, `/dev/tcp` sockets, reverse shells, and path tampering in a single routine.
  2. `checkTamperingCommand` (55 LOC): checking file copy/move (`cp`, `mv`, `install`, `rm`, `tee`), sed in-place modifications, and symlink creation without staging guards.
  3. Path target evaluation (`checkPathTarget`, `matchSystemPath`, `splitTargetDirectory`).
  4. Network execution checks (`checkBinaryCmd`, `collectPipelineStages`, `hasNetworkTool`, `checkCmdSubst`, `checkProcSubst`, `procSubstOutputExecuted`, and 51 LOC `cmdSubstOutputExecuted`).
- **Refactored Code:**
  - Extracted path tampering analysis into `internal/triage/pkgbuild/tampering.go` (180 LOC): modularized `checkTamperingCommand` into `checkCopyMoveTampering`, `checkSedTampering`, and `checkSymlinkTampering` (all <= 22 LOC).
  - Extracted network pipelines and command/process substitutions into `internal/triage/pkgbuild/net_exec.go` (235 LOC): decomposed `cmdSubstOutputExecuted` into `findAncestorsContext`, `isPipedToLaterShell`, and `cmdSubstOutputExecuted` (all <= 19 LOC).
  - Decomposed `checkCallExpr` in `rules.go` into `checkCallEval`, `checkCallBase64`, and `checkCallDevSocket` (all <= 26 LOC).
  - Reduced `internal/triage/pkgbuild/rules.go` from 594 LOC to 217 LOC (<= 300 LOC limit).
- **Expected Impact:**
  - `checkCallExpr` eliminated as >50 LOC violation.
  - `checkTamperingCommand` eliminated as >50 LOC violation.
  - `cmdSubstOutputExecuted` eliminated as >50 LOC violation.
  - `internal/triage/pkgbuild/rules.go` line count dropped from 594 LOC to 217 LOC (<= 300 LOC limit).
  - Net metric reduction of 4 violations (15 -> 11).

---

### [WAT-01] Oversized Filesystem Watcher, Debouncing Engine & Reconcile Loop

- **File & Location:** `internal/watcher/watcher.go:1-565`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  `internal/watcher/watcher.go` was 565 LOC (the last remaining file in the codebase exceeding the 300 LOC limit). It bundled core `fsnotify` directory registration, recursive tree walking, configuration parsing, debounce timer management, safe file readiness polling, event dispatching, and queue overflow reconciliation in a single oversized file.
- **Refactored Code:**
  - Extracted debounce timer lifecycle, event loop, file readiness polling, and event dispatching into `internal/watcher/debounce.go` (228 LOC).
  - Extracted queue overflow reconciliation and tree recovery walks into `internal/watcher/reconcile.go` (42 LOC).
  - Extracted `parseIgnoreExtensions` in `internal/watcher/watcher.go` to keep `New` concise and adopted `slices.Contains`.
  - Reduced `internal/watcher/watcher.go` from 565 LOC to 269 LOC (<= 300 LOC limit).
- **Expected Impact:**
  - Eliminated the last >300 LOC file violation across the entire repository (0 files >300 LOC remaining).
  - Net metric reduction of 1 violation (11 -> 10).

---

### [PKG-03] Oversized `ScorePKGBUILD` in PKGBUILD Scorer

- **File & Location:** `internal/triage/pkgbuild/scorer.go:13-95`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** Medium
- **Current State:**
  `ScorePKGBUILD` was an 82 LOC routine mixing:
  1. Trigger and dampener collection across both primary PKGBUILD analysis and optional `.install` scriptlet analysis.
  2. Threat score calculation, category accumulation, score ceiling clamping (100), and verdict classification (`VerdictQuarantine`, `VerdictAlert`, `VerdictPass`).
  3. Deduplication of applied dampeners and category sorting.
  4. Scriptlet file loading in `TriagePKGBUILD` intermixed with nested error checks and non-deferred descriptor management.
- **Refactored Code:**
  - Decomposed `ScorePKGBUILD` into `collectAnalysisTriggers` (10 LOC), `calculateVerdict` (27 LOC), `deduplicateDampeners` (14 LOC), and a concise `ScorePKGBUILD` (32 LOC).
  - Extracted `loadInstallScriptlet` (24 LOC) with structured `defer sf.Close()`.
- **Expected Impact:**
  - `ScorePKGBUILD` eliminated as >50 LOC violation.
  - Net metric reduction of 1 violation (10 -> 9).

---

### [PKG-04] Oversized `EvaluateIntegrity` in PKGBUILD Dampeners

- **File & Location:** `internal/triage/pkgbuild/dampeners.go:35-107`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** Medium
- **Current State:**
  `EvaluateIntegrity` was a 71 LOC function combining VCS exemption logic with missing checksum detection and an inline state-mutating closure (`checkSkip`) called sequentially across `Sha256sums`, `Sha512sums`, and `Md5sums`.
- **Refactored Code:**
  Decomposed `EvaluateIntegrity` into:
  - `EvaluateIntegrity` (16 LOC): guard conditions for install scriptlets, VCS packages, and configuration flags.
  - `evaluateSourceChecksums` (25 LOC): trigger construction for missing or SKIP checksums.
  - `hasAnyChecksums` (3 LOC): boolean predicate for presence of any hash algorithm.
  - `hasSkipChecksum` (10 LOC): variadic scanner inspecting multiple checksum slices for case-insensitive `SKIP` tokens.
- **Expected Impact:**
  - `EvaluateIntegrity` eliminated as >50 LOC violation (reduced from 71 LOC to 16 LOC).
  - Net metric reduction of 1 violation (9 -> 8).

---

### [BIN-03] Oversized `DetectFormat` in Binary Format Detector

- **File & Location:** `internal/triage/binary/detector.go:22-87`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** Medium
- **Current State:**
  `DetectFormat` spanned 65 LOC, combining shebang evaluation, ELF magic prefix checking, Mach-O endianness switching, FAT arch table boundary calculations, and PE MZ/PE signature offset extraction directly inside a single function body.
- **Refactored Code:**
  - Decomposed format probes into discrete predicates: `isScript` (3 LOC), `isELF` (3 LOC), `isMachO` (27 LOC), and `isPE` (21 LOC).
  - Streamlined `DetectFormat` into a concise 13-line declarative type switch.
- **Expected Impact:**
  - `DetectFormat` eliminated as >50 LOC violation.
  - Net metric reduction of 1 violation (8 -> 7).

---

### [BIN-04] Oversized `AnalyzePE` in Windows PE Analyzer

- **File & Location:** `internal/triage/binary/pe.go:19-78`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** Medium
- **Current State:**
  `AnalyzePE` was a 69 LOC routine handling UPX string verification, PE file instantiation, RWX section bitmasking, .text vs fallback entropy calculation, imported injection symbol inspection, capability slice scanning, and IOC scanning in a single long function.
- **Refactored Code:**
  - Decomposed section analysis into `inspectPESections` (29 LOC) with explicit RWX characteristic bitmasking and fallback entropy.
  - Decomposed symbol imports into `inspectPEImports` (12 LOC) detecting process injection APIs (`VirtualAllocEx`, `WriteProcessMemory`, etc.).
  - Extracted raw capability pattern scanning into `appendRawPECapabilities` (10 LOC).
  - Streamlined `AnalyzePE` into a 19-line coordinator.
- **Expected Impact:**
  - `AnalyzePE` eliminated as >50 LOC violation.
  - Net metric reduction of 1 violation (7 -> 6).

---

### [IPC-02] Oversized `call` in IPC Client

- **File & Location:** `internal/ipc/client.go:69-134`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** Medium
- **Current State:**
  `call` was a 65 LOC method in `internal/ipc/client.go` combining parameter serialization, sequence assignment, request packaging, transport failure handling with idempotent redials, JSON response unmarshaling, stream desynchronization checks, and response error decoding into a single routine.
- **Refactored Code:**
  - Decomposed request serialization into `prepareRequest` (18 LOC).
  - Decomposed transport exchange and idempotent retry logic into `executeExchange` (21 LOC).
  - Decomposed response validation and stream deserialization into `decodeResponse` (19 LOC).
  - Streamlined `call` into a concise 16 LOC coordinator.
- **Expected Impact:**
  - `call` eliminated as >50 LOC violation.
  - Net metric reduction of 1 violation (6 -> 5).

---

### [IPC-03] Oversized `handleConn` & `Start` Lifecycle Routines in IPC Server

- **File & Location:** `internal/ipc/server.go:76-299`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  `internal/ipc/server.go` combined server configuration with:
  1. `handleConn` (61 LOC): peer UID authentication, 10MB scanner buffer setup, read deadline enforcement, request JSON decoding, dispatch execution, response serialization, write deadline enforcement, and scanner error recovery.
  2. `Start` (59 LOC): stale socket detection, UNIX socket listener creation, permission chmod (0600), context-driven shutdown goroutine, and connection acceptance loop.
  3. Connection tracking (`trackConn`, `untrackConn`) and write error formatting (`writeError`).
- **Refactored Code:**
  - Extracted connection lifecycle into `internal/ipc/conn.go` (117 LOC), decomposing `handleConn` into `authenticateConn` (12 LOC), `processRequest` (17 LOC), and a streamlined `handleConn` loop (34 LOC).
  - Modularized `Start` in `internal/ipc/server.go` by extracting `createListener` (14 LOC) and `acceptLoop` (18 LOC), reducing `Start` to 30 LOC.
  - Reduced `internal/ipc/server.go` from 299 LOC to 210 LOC (<= 300 LOC limit).
- **Expected Impact:**
  - `handleConn` eliminated as >50 LOC violation.
  - `Start` eliminated as >50 LOC violation.
  - `internal/ipc/server.go` reduced from 299 LOC to 210 LOC.
  - Net metric reduction of 2 violations (5 -> 3).

---

### [QUA-02] Oversized `crossDeviceCopy` Routine in POSIX Move Implementation

- **File & Location:** `internal/quarantine/move_posix.go:57-114`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** Medium
- **Current State:**
  The `crossDeviceCopy` function (58 LOC) handled the cross-device (EXDEV) fallback relocation by intermixing source file descriptor opening & inode verification, temporary file creation, byte copying, fsyncing, permissions chmod (0600), destination atomic renaming, post-move source inode re-verification (anti-TOCTOU), and source deletion with rollback logic in a single procedure.
- **Refactored Code:**
  - Extracted temporary file copying and staging into `stageCrossDeviceFile` (28 LOC).
  - Extracted post-move source inode re-verification and unlinking with rollback protection into `verifyAndUnlinkSource` (18 LOC).
  - Streamlined `crossDeviceCopy` into a clear 19 LOC coordinator.
- **Expected Impact:**
  - `crossDeviceCopy` eliminated as >50 LOC violation.
  - Net metric reduction of 1 violation (3 -> 2).

---

### [PKG-05] Oversized `WalkScopeAncestors` AST Traversal in PKGBUILD Parser

- **File & Location:** `internal/triage/pkgbuild/parser.go:197-251`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** Low
- **Current State:**
  `WalkScopeAncestors` (55 LOC) contained two distinct AST traversal implementations inside a single branching function: a simplified stack-tracking traversal for `.install` scriptlets and a function-depth-tracking traversal for PKGBUILD ASTs.
- **Refactored Code:**
  - Extracted `.install` scriptlet walk into `walkInstallScriptAncestors` (17 LOC).
  - Extracted PKGBUILD function-depth walk into `walkPKGBUILDAncestors` (32 LOC).
  - Streamlined `WalkScopeAncestors` into a 11 LOC dispatcher.
- **Expected Impact:**
  - `WalkScopeAncestors` eliminated as >50 LOC violation.
  - Net metric reduction of 1 violation (2 -> 1).

---

### [CMD-01] Monolithic 83 LOC Daemon `run` Coordinator in Main Entrypoint

- **File & Location:** `cmd/quarantined/main.go:92-174`
- **Issue Category:** Spaghetti & Architecture
- **Severity:** High
- **Current State:**
  `cmd/quarantined/main.go` implemented the entire daemon lifecycle inside a single 83 LOC `run` function. Initialization of vault, watcher, pipeline, and IPC server was entangled with the select event loop (handling OS signals, hourly retention sweeps, IPC server errors, watcher event dispatching, and error logging) and sequential shutdown logic.
- **Refactored Code:**
  - Extracted vault initialization and limit configuration into `initVault` (11 LOC).
  - Extracted watcher initialization into `initWatcher` (11 LOC).
  - Extracted IPC server startup into `startIPC` (10 LOC).
  - Extracted event handling select loop into `runEventLoop` (43 LOC).
  - Streamlined `run` into a clean 33 LOC coordinator.
- **Expected Impact:**
  - `run` eliminated as >50 LOC violation.
  - Final hotspot eliminated across the entire codebase.
  - Net metric reduction of 1 violation (1 -> 0).
