package input

import (
	"net"
)

func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateBlocks := []*net.IPNet{
		// IPv4 private range
		{IP: net.IPv4(10,0,0,0), Mask: net.CIDRMask(8,32)},
		{IP: net.IPv4(172,16,0,0), Mask: net.CIDRMask(12,32)},
		{IP: net.IPv4(192,168,0,0), Mask: net.CIDRMask(16,32)},
		// IPv6 unique local
		{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7,128)},
		// IPv6 link-local
		{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(10,128)},
	}

	// Check private ranges
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	
	// also skip loopback and unspecified
	return ip.IsLoopback() || ip.IsUnspecified()
}
