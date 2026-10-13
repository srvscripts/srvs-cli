//go:build !windows

package resolver

// systemServers returns the configured DNS servers: the nameserver lines of /etc/resolv.conf.
func systemServers() []string { return serversFromResolvConf("/etc/resolv.conf") }
