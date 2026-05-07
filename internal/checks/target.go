package checks

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var hostLabelRE = regexp.MustCompile(`^[a-zA-Z0-9-]{1,63}$`)

func NormalizeTarget(input string) (Target, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}

	normalized := raw
	if strings.HasPrefix(strings.ToLower(normalized), "http://") || strings.HasPrefix(strings.ToLower(normalized), "https://") {
		u, err := url.Parse(normalized)
		if err != nil {
			return Target{}, fmt.Errorf("invalid URL: %w", err)
		}
		normalized = u.Host
	}

	normalized = strings.Trim(normalized, "/")
	if normalized == "" {
		return Target{}, fmt.Errorf("missing host")
	}

	host := normalized
	port := "443"

	if strings.Contains(normalized, ":") {
		if h, p, err := net.SplitHostPort(normalized); err == nil {
			host, port = h, p
		} else if strings.Count(normalized, ":") == 1 {
			parts := strings.SplitN(normalized, ":", 2)
			host = parts[0]
			if parts[1] != "" {
				port = parts[1]
			}
		}
	}

	host = strings.Trim(host, "[]")
	if host == "" {
		return Target{}, fmt.Errorf("missing hostname")
	}
	if !isValidHost(host) {
		return Target{}, fmt.Errorf("invalid hostname format: %s", host)
	}
	if port == "" {
		port = "443"
	}

	return Target{
		Raw:      raw,
		Input:    normalized,
		Host:     host,
		Port:     port,
		HostPort: net.JoinHostPort(host, port),
	}, nil
}

func isValidHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if !hostLabelRE.MatchString(p) || strings.HasPrefix(p, "-") || strings.HasSuffix(p, "-") {
			return false
		}
	}
	return true
}
