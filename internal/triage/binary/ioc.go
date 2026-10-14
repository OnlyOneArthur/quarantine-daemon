package binary

import (
	"bytes"
	"net/netip"
)

var (
	iocPatterns = []string{"/dev/tcp/", "sh -i", "bash -i", "| sh", "| bash", "|/bin/sh", "|/bin/bash"}
	capStrings  = []string{"memfd_create", "process_vm_writev", "VirtualAllocEx", "ptrace"}

	iocPatternBytes = [][]byte{
		[]byte("/dev/tcp/"),
		[]byte("sh -i"),
		[]byte("bash -i"),
		[]byte("| sh"),
		[]byte("| bash"),
		[]byte("|/bin/sh"),
		[]byte("|/bin/bash"),
	}
	capBytes = [][]byte{
		[]byte("memfd_create"),
		[]byte("process_vm_writev"),
		[]byte("VirtualAllocEx"),
		[]byte("ptrace"),
	}
)

// scanRawIOCs inspects bytes for shell payloads and non-private C2 IPv4 addresses.
func scanRawIOCs(data []byte) []string {
	var iocs []string
	for i, p := range iocPatternBytes {
		if bytes.Contains(data, p) {
			iocs = append(iocs, iocPatterns[i])
		}
	}

	seen := make(map[string]struct{}, len(iocs))
	for _, x := range iocs {
		seen[x] = struct{}{}
	}

	// Non-private C2 IP detection
	forEachIPv4(data, 100, func(m []byte) {
		addr, err := netip.ParseAddr(string(m))
		if err != nil || !addr.Is4() {
			return
		}
		// Skip unspecified, loopback, private, link-local, multicast, or broadcast
		if addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
			addr.IsLinkLocalUnicast() || addr.IsMulticast() {
			return
		}
		b := addr.As4()
		if b[0] == 0 || (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) {
			return
		}
		ipStr := addr.String()
		// Skip common public DNS resolvers and benign infrastructure
		switch ipStr {
		case "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220":
			return
		}
		ioc := "public-c2-ip:" + ipStr
		if _, exists := seen[ioc]; !exists {
			seen[ioc] = struct{}{}
			iocs = append(iocs, ioc)
		}
	})
	return iocs
}

// forEachIPv4 scans ASCII addresses with regexp \b boundaries and at most limit matches.
func forEachIPv4(data []byte, limit int, visit func([]byte)) {
	for i, count := 0, 0; i < len(data) && count < limit; i++ {
		if !isDigitByte(data[i]) || i > 0 && isWordByte(data[i-1]) {
			continue
		}
		end, ok := parseIPv4Candidate(data, i)
		if !ok || end < len(data) && isWordByte(data[end]) {
			continue
		}
		visit(data[i:end])
		count++
		i = end - 1
	}
}

func isDigitByte(b byte) bool {
	return b >= '0' && b <= '9'
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func parseIPv4Candidate(data []byte, start int) (int, bool) {
	i := start
	for octet := range 4 {
		begin, value := i, 0
		for i < len(data) && data[i] >= '0' && data[i] <= '9' && i-begin < 3 {
			value = value*10 + int(data[i]-'0')
			i++
		}
		if i == begin || value > 255 || i < len(data) && data[i] >= '0' && data[i] <= '9' {
			return start, false
		}
		if octet < 3 {
			if i == len(data) || data[i] != '.' {
				return start, false
			}
			i++
		}
	}
	return i, true
}
