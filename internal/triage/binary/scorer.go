package binary

import (
	"bytes"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/triage/entropy"
)

// Verdict defines the triage action verdict.
type Verdict string

const (
	VerdictPass       Verdict = "PASS"
	VerdictAlert      Verdict = "ALERT"
	VerdictQuarantine Verdict = "QUARANTINE"
)

// Risk category identifiers.
const (
	CategoryStructure    = "structure"
	CategoryEntropy      = "entropy"
	CategoryCapabilities = "capabilities"
	CategoryIOC          = "ioc"
)

// ThreatTrigger records a single security rule hit with its category and score weight.
type ThreatTrigger struct {
	Category    string `json:"category"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ScoreWeight int    `json:"score_weight"`
}

// TriageResult contains the final threat score, verdict, and supporting evidence.
type TriageResult struct {
	Path             string          `json:"path"`
	Format           Format          `json:"format"`
	Score            int             `json:"score"`
	Verdict          Verdict         `json:"verdict"`
	Entropy          float64         `json:"entropy"`
	Triggers         []ThreatTrigger `json:"triggers"`
	CategoriesHit    []string        `json:"categories_hit"`
	DampenersApplied []string        `json:"dampeners_applied"`
	IsGoBinary       bool            `json:"is_go_binary"`
	IsRustBinary     bool            `json:"is_rust_binary"`
}

func calculateCappedScore(triggers []ThreatTrigger, isGo, isRust bool, quarantineThreshold int) (int, Verdict, []string) {
	var (
		scoreStructure    = 0
		scoreEntropy      = 0
		scoreCapabilities = 0
		scoreIOC          = 0
		dampeners         []string
		categoryMap       = make(map[string]struct{})
	)

	for _, tr := range triggers {
		categoryMap[tr.Category] = struct{}{}
		switch tr.Category {
		case CategoryStructure:
			scoreStructure += tr.ScoreWeight
		case CategoryEntropy:
			scoreEntropy += tr.ScoreWeight
		case CategoryCapabilities:
			scoreCapabilities += tr.ScoreWeight
		case CategoryIOC:
			scoreIOC += tr.ScoreWeight
		}
	}

	// Cap entropy, capabilities, and IOC contributions; structure remains uncapped.
	if scoreEntropy > 40 {
		scoreEntropy = 40
	}
	if scoreCapabilities > 40 {
		scoreCapabilities = 40
	}
	if scoreIOC > 50 {
		scoreIOC = 50
	}

	total := scoreStructure + scoreEntropy + scoreCapabilities + scoreIOC

	if isGo {
		total -= 25
		dampeners = append(dampeners, "go_runtime_dampener (-25)")
	}
	if isRust {
		total -= 25
		dampeners = append(dampeners, "rust_runtime_dampener (-25)")
	}

	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}

	verdict := VerdictPass
	if total >= quarantineThreshold {
		if len(categoryMap) >= 2 {
			verdict = VerdictQuarantine
		} else {
			// Downgrade to Alert if fewer than 2 independent categories hit
			verdict = VerdictAlert
			total = quarantineThreshold - 1
		}
	} else if total >= 50 {
		verdict = VerdictAlert
	}

	return total, verdict, dampeners
}

// ScoreELF computes the correlated multi-category threat score for an ELF analysis.
func ScoreELF(analysis *ELFAnalysis, cfg *config.Config, path string) *TriageResult {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	entropyThreshold := cfg.Binary.EntropyThreshold
	if entropyThreshold <= 0 {
		entropyThreshold = 7.3
	}

	quarantineThreshold := cfg.Quarantine.ThresholdScore
	if quarantineThreshold <= 0 {
		quarantineThreshold = 85
	}

	res := &TriageResult{
		Path:         path,
		Format:       FormatELF,
		Entropy:      analysis.TextEntropy,
		IsGoBinary:   analysis.IsGoBinary,
		IsRustBinary: analysis.IsRustBinary,
	}

	// --- Category 1: Structure & Header Integrity ---
	if analysis.CorruptedSectionHeaders && analysis.HasValidPTLoad {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryStructure,
			Name:        "corrupted_section_headers_evasion",
			Description: "Corrupted section headers with valid executable PT_LOAD segments indicate deliberate evasion",
			ScoreWeight: 40,
		})
	}

	if analysis.HasExecutableStack {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryStructure,
			Name:        "executable_stack",
			Description: "PT_GNU_STACK marked executable (PF_X)",
			ScoreWeight: 35,
		})
	}

	if analysis.HasRWXSegments {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryStructure,
			Name:        "rwx_segment",
			Description: "Loadable segment marked readable, writable, and executable (RWX)",
			ScoreWeight: 35,
		})
	}

	// --- Category 2: Packing & Entropy ---
	if analysis.TextEntropy > entropyThreshold {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryEntropy,
			Name:        "high_text_entropy",
			Description: "Executable section entropy exceeds threshold, indicating packing or encryption",
			ScoreWeight: 25,
		})
	}

	if analysis.HasUPX {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryEntropy,
			Name:        "upx_packed",
			Description: "Binary packed with UPX packer",
			ScoreWeight: 30,
		})
	}

	// --- Category 3: High-Risk Capabilities & Injection APIs ---
	for _, capName := range analysis.SuspiciousCapabilities {
		switch capName {
		case "memfd_create", "process_vm_writev", "VirtualAllocEx", "ptrace":
			res.Triggers = append(res.Triggers, ThreatTrigger{
				Category:    CategoryCapabilities,
				Name:        "injection_api_" + capName,
				Description: "High-risk process injection/memory execution API detected: " + capName,
				ScoreWeight: 20,
			})
		}
	}

	// --- Category 4: IOC & Reverse Shell Payloads ---
	for _, ioc := range analysis.SuspiciousIOCs {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryIOC,
			Name:        "ioc_payload",
			Description: "Suspicious payload or network IOC pattern detected: " + ioc,
			ScoreWeight: 35,
		})
	}

	score, verdict, dampeners := calculateCappedScore(res.Triggers, res.IsGoBinary, res.IsRustBinary, quarantineThreshold)
	res.Score = score
	res.Verdict = verdict
	res.DampenersApplied = dampeners

	catMap := make(map[string]struct{})
	for _, tr := range res.Triggers {
		catMap[tr.Category] = struct{}{}
	}
	for cat := range catMap {
		res.CategoriesHit = append(res.CategoriesHit, cat)
	}

	return res
}

// ScorePE computes the correlated multi-category threat score for a Windows PE binary.
func ScorePE(analysis *PEAnalysis, cfg *config.Config, path string) *TriageResult {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	entropyThreshold := cfg.Binary.EntropyThreshold
	if entropyThreshold <= 0 {
		entropyThreshold = 7.3
	}

	quarantineThreshold := cfg.Quarantine.ThresholdScore
	if quarantineThreshold <= 0 {
		quarantineThreshold = 85
	}

	res := &TriageResult{
		Path:    path,
		Format:  FormatPE,
		Entropy: analysis.TextEntropy,
	}

	if analysis.HasRWXSections {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryStructure,
			Name:        "pe_rwx_section",
			Description: "PE section marked executable and writable",
			ScoreWeight: 35,
		})
	}

	if analysis.TextEntropy > entropyThreshold {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryEntropy,
			Name:        "pe_high_entropy",
			Description: "PE section entropy exceeds threshold",
			ScoreWeight: 25,
		})
	}

	if analysis.HasUPX {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryEntropy,
			Name:        "upx_packed",
			Description: "Binary packed with UPX packer",
			ScoreWeight: 30,
		})
	}

	for _, capName := range analysis.SuspiciousCapabilities {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryCapabilities,
			Name:        "pe_injection_api_" + capName,
			Description: "Process injection API imported: " + capName,
			ScoreWeight: 20,
		})
	}

	for _, ioc := range analysis.SuspiciousIOCs {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryIOC,
			Name:        "ioc_payload",
			Description: "Suspicious payload or network IOC pattern detected: " + ioc,
			ScoreWeight: 35,
		})
	}

	score, verdict, dampeners := calculateCappedScore(res.Triggers, false, false, quarantineThreshold)
	res.Score = score
	res.Verdict = verdict
	res.DampenersApplied = dampeners

	catMap := make(map[string]struct{})
	for _, tr := range res.Triggers {
		catMap[tr.Category] = struct{}{}
	}
	for cat := range catMap {
		res.CategoriesHit = append(res.CategoriesHit, cat)
	}

	return res
}

// ScoreMachO computes the threat score for a macOS Mach-O binary.
func ScoreMachO(analysis *MachOAnalysis, cfg *config.Config, path string) *TriageResult {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	entropyThreshold := cfg.Binary.EntropyThreshold
	if entropyThreshold <= 0 {
		entropyThreshold = 7.3
	}

	quarantineThreshold := cfg.Quarantine.ThresholdScore
	if quarantineThreshold <= 0 {
		quarantineThreshold = 85
	}

	res := &TriageResult{
		Path:    path,
		Format:  FormatMachO,
		Entropy: analysis.TextEntropy,
	}

	if analysis.HasRWXSegments {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryStructure,
			Name:        "macho_rwx_segment",
			Description: "Mach-O segment marked readable, writable, executable",
			ScoreWeight: 35,
		})
	}

	if analysis.TextEntropy > entropyThreshold {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryEntropy,
			Name:        "macho_high_entropy",
			Description: "Mach-O text entropy exceeds threshold",
			ScoreWeight: 25,
		})
	}

	if analysis.HasUPX {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryEntropy,
			Name:        "upx_packed",
			Description: "Binary packed with UPX packer",
			ScoreWeight: 30,
		})
	}

	for _, capName := range analysis.SuspiciousCapabilities {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryCapabilities,
			Name:        "injection_api_" + capName,
			Description: "High-risk process injection/memory execution API detected: " + capName,
			ScoreWeight: 20,
		})
	}

	for _, ioc := range analysis.SuspiciousIOCs {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryIOC,
			Name:        "ioc_payload",
			Description: "Suspicious payload or network IOC pattern detected: " + ioc,
			ScoreWeight: 35,
		})
	}

	score, verdict, dampeners := calculateCappedScore(res.Triggers, false, false, quarantineThreshold)
	res.Score = score
	res.Verdict = verdict
	res.DampenersApplied = dampeners

	catMap := make(map[string]struct{})
	for _, tr := range res.Triggers {
		catMap[tr.Category] = struct{}{}
	}
	for cat := range catMap {
		res.CategoriesHit = append(res.CategoriesHit, cat)
	}

	return res
}

// TriageBinary analyzes a byte slice of binary or script data, detects format,
// evaluates security rules, and returns a TriageResult.
func TriageBinary(data []byte, path string, cfg *config.Config) (*TriageResult, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	format := DetectFormat(data)

	switch format {
	case FormatELF:
		analysis, err := AnalyzeELF(data)
		if err != nil {
			return nil, err
		}
		res := ScoreELF(analysis, cfg, path)
		res.Format = FormatELF
		return res, nil

	case FormatPE:
		analysis, err := AnalyzePE(data)
		if err != nil {
			return nil, err
		}
		res := ScorePE(analysis, cfg, path)
		res.Format = FormatPE
		return res, nil

	case FormatMachO:
		analysis, err := AnalyzeMachO(data)
		if err != nil {
			return nil, err
		}
		res := ScoreMachO(analysis, cfg, path)
		res.Format = FormatMachO
		return res, nil
	}

	// For scripts or unknown formats: calculate entropy and inspect for UPX/IOCs/capabilities
	ent := entropy.Calculate(data)
	entropyThreshold := cfg.Binary.EntropyThreshold
	if entropyThreshold <= 0 {
		entropyThreshold = 7.3
	}

	quarantineThreshold := cfg.Quarantine.ThresholdScore
	if quarantineThreshold <= 0 {
		quarantineThreshold = 85
	}

	res := &TriageResult{
		Path:    path,
		Format:  format,
		Entropy: ent,
	}

	if bytes.Contains(data, []byte("UPX!")) {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryEntropy,
			Name:        "upx_packed",
			Description: "Binary packed with UPX packer",
			ScoreWeight: 30,
		})
	}

	if ent > entropyThreshold && len(data) > 512 {
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryEntropy,
			Name:        "high_entropy",
			Description: "Payload entropy exceeds threshold",
			ScoreWeight: 25,
		})
	}

	for _, c := range capStrings {
		if bytes.Contains(data, []byte(c)) {
			res.Triggers = append(res.Triggers, ThreatTrigger{
				Category:    CategoryCapabilities,
				Name:        "injection_api_" + c,
				Description: "High-risk process injection API detected: " + c,
				ScoreWeight: 20,
			})
		}
	}

	for _, ioc := range scanRawIOCs(data) {
		description := "Suspicious payload or network pattern detected: " + ioc
		if strings.HasPrefix(ioc, "public-c2-ip:") {
			description = "Public C2 IP detected: " + strings.TrimPrefix(ioc, "public-c2-ip:")
		}
		res.Triggers = append(res.Triggers, ThreatTrigger{
			Category:    CategoryIOC,
			Name:        "ioc_payload",
			Description: description,
			ScoreWeight: 35,
		})
	}

	if bytes.Contains(data, []byte("runtime.main")) || bytes.Contains(data, []byte("Go build ID:")) {
		res.IsGoBinary = true
	}
	if bytes.Contains(data, []byte("rust_panic")) || bytes.Contains(data, []byte("__rust_alloc")) {
		res.IsRustBinary = true
	}

	score, verdict, dampeners := calculateCappedScore(res.Triggers, res.IsGoBinary, res.IsRustBinary, quarantineThreshold)
	res.Score = score
	res.Verdict = verdict
	res.DampenersApplied = dampeners

	catMap := make(map[string]struct{})
	for _, tr := range res.Triggers {
		catMap[tr.Category] = struct{}{}
	}
	for cat := range catMap {
		res.CategoriesHit = append(res.CategoriesHit, cat)
	}

	return res, nil
}
