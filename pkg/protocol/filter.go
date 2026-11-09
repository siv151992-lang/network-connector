package protocol

import "net/netip"

// Allowed evaluates filter rules for a new inbound flow: src address, IP
// protocol number and (TCP/UDP) destination port. Default deny.
func Allowed(rules []FilterRule, src netip.Addr, proto int, port uint16) bool {
	for _, r := range rules {
		if !containsAddr(r.SrcIPs, src) {
			continue
		}
		if len(r.Protos) > 0 && !containsInt(r.Protos, proto) {
			continue
		}
		if len(r.Ports) == 0 {
			return true
		}
		if proto != ProtoTCP && proto != ProtoUDP {
			// Portless protocols (ICMP, …) only match rules that allow every
			// port; "tag:web:443" must not also open ICMP.
			for _, pr := range r.Ports {
				if pr == AllPorts {
					return true
				}
			}
			continue
		}
		for _, pr := range r.Ports {
			if pr.Contains(port) {
				return true
			}
		}
	}
	return false
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
