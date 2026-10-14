package binary

import (
	"bytes"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

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

	return triageRawPayload(data, path, format, cfg), nil
}

func triageRawPayload(data []byte, path string, format Format, cfg *config.Config) *TriageResult {
	entThresh, qThresh := resolveThresholds(cfg)
	ent := CalculateEntropy(data)
	triggers := detectRawTriggers(data, ent, entThresh)
	isGo, isRust := detectRuntimeMarkers(data)

	res := &TriageResult{
		Path:         path,
		Format:       format,
		Entropy:      ent,
		Triggers:     triggers,
		IsGoBinary:   isGo,
		IsRustBinary: isRust,
	}
	return finalizeResult(res, isGo, isRust, qThresh)
}

func detectRawTriggers(data []byte, ent, entropyThreshold float64) []ThreatTrigger {
	var triggers []ThreatTrigger

	if bytes.Contains(data, []byte("UPX!")) {
		triggers = append(triggers, ThreatTrigger{
			Category:    CategoryEntropy,
			Name:        "upx_packed",
			Description: "Binary packed with UPX packer",
			ScoreWeight: 30,
		})
	}

	if ent > entropyThreshold && len(data) > 512 {
		triggers = append(triggers, ThreatTrigger{
			Category:    CategoryEntropy,
			Name:        "high_entropy",
			Description: "Payload entropy exceeds threshold",
			ScoreWeight: 25,
		})
	}

	for i, c := range capBytes {
		if bytes.Contains(data, c) {
			capName := capStrings[i]
			triggers = append(triggers, ThreatTrigger{
				Category:    CategoryCapabilities,
				Name:        "injection_api_" + capName,
				Description: "High-risk process injection API detected: " + capName,
				ScoreWeight: 20,
			})
		}
	}

	for _, ioc := range scanRawIOCs(data) {
		description := "Suspicious payload or network pattern detected: " + ioc
		if ip, ok := strings.CutPrefix(ioc, "public-c2-ip:"); ok {
			description = "Public C2 IP detected: " + ip
		}
		triggers = append(triggers, ThreatTrigger{
			Category:    CategoryIOC,
			Name:        "ioc_payload",
			Description: description,
			ScoreWeight: 35,
		})
	}

	return triggers
}

func detectRuntimeMarkers(data []byte) (isGo bool, isRust bool) {
	if bytes.Contains(data, []byte("runtime.main")) || bytes.Contains(data, []byte("Go build ID:")) {
		isGo = true
	}
	if bytes.Contains(data, []byte("rust_panic")) || bytes.Contains(data, []byte("__rust_alloc")) {
		isRust = true
	}
	return isGo, isRust
}
