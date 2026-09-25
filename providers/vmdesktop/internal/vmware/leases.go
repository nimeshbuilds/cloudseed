package vmware

import (
	"os"
	"regexp"
	"strings"
)

var leaseRe = regexp.MustCompile(`(?s)lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)\}`)
var macRe = regexp.MustCompile(`hardware ethernet\s+([0-9a-fA-F:]+)`)

// LeaseIP returns the most recent DHCP lease for a MAC across the host's lease files.
func (h *Host) LeaseIP(mac string) string {
	mac = strings.ToLower(mac)
	for _, f := range h.LeaseFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		ip := ""
		for _, m := range leaseRe.FindAllStringSubmatch(string(data), -1) {
			if mm := macRe.FindStringSubmatch(m[2]); mm != nil && strings.ToLower(mm[1]) == mac {
				ip = m[1] // last one wins (files are append-only)
			}
		}
		if ip != "" {
			return ip
		}
	}
	return ""
}
