package pkgbuild

import (
	"net"
	"net/url"
	"strings"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

var legitimateForges = map[string]struct{}{
	"github.com":       {},
	"gitlab.com":       {},
	"codeberg.org":     {},
	"archlinux.org":    {},
	"gnu.org":          {},
	"savannah.gnu.org": {},
	"sourceforge.net":  {},
	"pypi.org":         {},
	"crates.io":        {},
	"cpan.org":         {},
	"kernel.org":       {},
}

var urlShorteners = map[string]struct{}{
	"bit.ly":      {},
	"t.co":        {},
	"tinyurl.com": {},
	"is.gd":       {},
	"buff.ly":     {},
}

var pastebinSites = map[string]struct{}{
	"pastebin.com": {},
	"hastebin.com": {},
	"ghostbin.com": {},
}

var discordCDNs = map[string]struct{}{
	"cdn.discordapp.com":   {},
	"media.discordapp.net": {},
}

// cleanSourceURL normalizes VCS prefixes and :: alias prefixes from source specs.
func cleanSourceURL(src string) string {
	rawURL := src
	if idx := strings.Index(rawURL, "::"); idx != -1 {
		// Only treat "::" as a VCS name separator (pkgname::url); never
		// strip when it appears after the URL scheme (e.g. IPv6 literals).
		if scheme := strings.Index(rawURL, "://"); scheme == -1 || idx < scheme {
			rawURL = rawURL[idx+2:]
		}
	}
	for _, proto := range []string{"git+", "svn+", "hg+", "bzr+"} {
		if cut, ok := strings.CutPrefix(rawURL, proto); ok {
			rawURL = cut
			break
		}
	}
	return rawURL
}

func classifyUntrustedHost(host string, line int) (ThreatTrigger, bool) {
	if ip := net.ParseIP(host); ip != nil {
		desc := "Source URL uses raw IPv4 address: " + host
		if ip.To4() == nil {
			desc = "Source URL uses raw IPv6 address: " + host
		}
		return ThreatTrigger{
			Category:    CategoryUntrustedSource,
			Name:        "untrusted_source_raw_ip",
			Description: desc,
			ScoreWeight: 30,
			Line:        line,
			Scope:       ScopeRoot,
		}, true
	}

	for _, spec := range []struct {
		hosts map[string]struct{}
		name  string
		desc  string
	}{
		{urlShorteners, "untrusted_source_shortener", "Source URL uses URL shortener: " + host},
		{pastebinSites, "untrusted_source_pastebin", "Source URL hosted on pastebin service: " + host},
		{discordCDNs, "untrusted_source_discord_cdn", "Source URL hosted on Discord CDN: " + host},
	} {
		if isHostMatch(host, spec.hosts) {
			return ThreatTrigger{
				Category:    CategoryUntrustedSource,
				Name:        spec.name,
				Description: spec.desc,
				ScoreWeight: 30,
				Line:        line,
				Scope:       ScopeRoot,
			}, true
		}
	}
	return ThreatTrigger{}, false
}

// CheckUntrustedSources inspects extracted source URLs in source=() for security risks.
func CheckUntrustedSources(analysis *Analysis, cfg *config.Config) []ThreatTrigger {
	var triggers []ThreatTrigger
	if len(analysis.Source) == 0 {
		return triggers
	}

	blockPolicy := true
	if cfg != nil {
		blockPolicy = cfg.PKGBUILD.BlockUntrustedSources
	}

	untrustedCount := 0
	for i, src := range analysis.Source {
		line := 1
		if i < len(analysis.SourceLines) && analysis.SourceLines[i] > 0 {
			line = analysis.SourceLines[i]
		}

		u, err := url.Parse(cleanSourceURL(src))
		if err != nil || u == nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" || isLegitimateForge(host) {
			continue
		}

		if t, ok := classifyUntrustedHost(host, line); ok {
			triggers = append(triggers, t)
			untrustedCount++
		}
	}

	if untrustedCount > 0 && blockPolicy {
		triggers = append(triggers, ThreatTrigger{
			Category:    CategoryUntrustedSource,
			Name:        "untrusted_source_blocked",
			Description: "Untrusted source link flagged by daemon security policy",
			ScoreWeight: 25,
			Line:        triggers[0].Line,
			Scope:       ScopeRoot,
		})
	}

	return triggers
}

func isLegitimateForge(host string) bool {
	return isHostMatch(host, legitimateForges)
}

func isHostMatch(host string, hosts map[string]struct{}) bool {
	if _, ok := hosts[host]; ok {
		return true
	}
	for h := range hosts {
		if strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}
