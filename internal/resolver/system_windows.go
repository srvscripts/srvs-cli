//go:build windows

package resolver

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemServers returns the DNS servers configured on the network adapters that are up, in adapter order
// (the same list "ipconfig /all" shows). Windows has no /etc/resolv.conf.
func systemServers() []string {
	size := uint32(16 * 1024)
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_FRIENDLY_NAME, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var ips []net.IP
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				ips = append(ips, d.Address.IP())
			}
		}
		return usableDNS(ips)
	}
	return nil
}
