package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"tyssldoc/internal/checks"
)

type Report struct {
	Version   string            `json:"version"`
	CheckedAt time.Time         `json:"checked_at"`
	Target    checks.Target     `json:"target"`
	DNS       checks.DNSResult  `json:"dns"`
	TLS       checks.TLSResult  `json:"tls"`
	HTTP      checks.HTTPResult `json:"http"`
	ExitCode  int               `json:"exit_code"`
}

func DeriveExitCode(r *Report) int {
	if hasCriticalFailure(r) {
		return 2
	}
	if hasWarning(r) {
		return 1
	}
	return 0
}

func hasCriticalFailure(r *Report) bool {
	if len(r.TLS.Failures) > 0 || len(r.HTTP.Failures) > 0 || len(r.DNS.Failures) > 0 {
		return true
	}
	if r.TLS.Cert != nil && r.TLS.Cert.DaysRemaining < 0 {
		return true
	}
	if !r.TLS.HostnameValid {
		return true
	}
	if !r.TLS.Reachable || !r.HTTP.HTTPSReachable {
		return true
	}
	return false
}

func hasWarning(r *Report) bool {
	return len(r.TLS.Warnings) > 0 || len(r.HTTP.Warnings) > 0 || len(r.DNS.Warnings) > 0
}

func PrintHuman(w io.Writer, r *Report) {
	fmt.Fprintf(w, "Target: %s\n", r.Target.HostPort)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "TLS:")
	if r.TLS.Reachable {
		printStatus(w, "OK", "TLS handshake succeeded")
	} else {
		printStatus(w, "FAIL", "TLS handshake failed")
	}
	if r.TLS.ChainValid {
		printStatus(w, "OK", "Certificate chain trusted")
	}
	if r.TLS.HostnameValid {
		printStatus(w, "OK", "Hostname matches certificate")
	}
	if r.TLS.TLSVersion != "" {
		printStatus(w, "INFO", "TLS version: "+r.TLS.TLSVersion)
	}
	if r.TLS.CipherSuite != "" {
		printStatus(w, "INFO", "Cipher suite: "+r.TLS.CipherSuite)
	}
	if r.TLS.ALPN != "" {
		printStatus(w, "INFO", "ALPN: "+r.TLS.ALPN)
	}
	if r.TLS.HandshakeTime != "" {
		printStatus(w, "INFO", "Handshake time: "+r.TLS.HandshakeTime)
	}
	for _, msg := range r.TLS.Warnings {
		printStatus(w, "WARN", msg)
	}
	for _, msg := range r.TLS.Failures {
		printStatus(w, "FAIL", msg)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Certificate:")
	if r.TLS.Cert == nil {
		printStatus(w, "FAIL", "No certificate details available")
	} else {
		fmt.Fprintf(w, "  Subject: %s\n", r.TLS.Cert.Subject)
		fmt.Fprintf(w, "  Issuer: %s\n", r.TLS.Cert.Issuer)
		fmt.Fprintf(w, "  Serial: %s\n", r.TLS.Cert.SerialNumber)
		fmt.Fprintf(w, "  Valid From: %s\n", r.TLS.Cert.NotBefore)
		fmt.Fprintf(w, "  Valid Until: %s\n", r.TLS.Cert.NotAfter)
		fmt.Fprintf(w, "  Days Remaining: %d\n", r.TLS.Cert.DaysRemaining)
		fmt.Fprintln(w, "  SANs:")
		for _, san := range r.TLS.Cert.SANs {
			fmt.Fprintf(w, "  - %s\n", san)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Certificate Chain:")
	if len(r.TLS.Chain) == 0 {
		printStatus(w, "WARN", "No chain details found")
	} else {
		for i, c := range r.TLS.Chain {
			fmt.Fprintf(w, "  %d. Subject: %s\n", i+1, c.Subject)
			fmt.Fprintf(w, "     Issuer: %s\n", c.Issuer)
			fmt.Fprintf(w, "     Serial: %s\n", c.SerialNumber)
			fmt.Fprintf(w, "     Not After: %s\n", c.NotAfter)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "HTTP:")
	if r.HTTP.HTTPSReachable {
		printStatus(w, "OK", fmt.Sprintf("HTTPS reachable (%d)", r.HTTP.HTTPSStatusCode))
	} else {
		printStatus(w, "FAIL", "HTTPS unreachable")
	}
	if r.HTTP.HTTPRedirectsHTTPS {
		printStatus(w, "OK", "HTTP redirects to HTTPS")
	} else {
		printStatus(w, "WARN", "HTTP does not redirect to HTTPS")
	}
	if r.HTTP.HSTS != "" {
		printStatus(w, "OK", "HSTS enabled")
	} else {
		printStatus(w, "WARN", "HSTS missing")
	}
	if r.HTTP.FinalURL != "" {
		printStatus(w, "INFO", "Final URL: "+r.HTTP.FinalURL)
	}
	for _, msg := range r.HTTP.Warnings {
		if !strings.Contains(msg, "does not redirect") && !strings.Contains(strings.ToLower(msg), "hsts") {
			printStatus(w, "WARN", msg)
		}
	}
	for _, msg := range r.HTTP.Failures {
		printStatus(w, "FAIL", msg)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Security Headers:")
	keys := make([]string, 0, len(r.HTTP.SecurityHeaders))
	for k := range r.HTTP.SecurityHeaders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := r.HTTP.SecurityHeaders[k]
		if v == "" {
			fmt.Fprintf(w, "  %s: (missing)\n", k)
		} else {
			fmt.Fprintf(w, "  %s: %s\n", k, v)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "DNS:")
	if len(r.DNS.ARecords) > 0 {
		printStatus(w, "INFO", "A records: "+strings.Join(r.DNS.ARecords, ", "))
	} else {
		printStatus(w, "WARN", "No A records found")
	}
	if len(r.DNS.AAAARecords) > 0 {
		printStatus(w, "INFO", "AAAA records: "+strings.Join(r.DNS.AAAARecords, ", "))
	} else {
		printStatus(w, "WARN", "No AAAA records found")
	}
	if r.DNS.CNAME != "" {
		printStatus(w, "INFO", "CNAME: "+r.DNS.CNAME)
	}
	for _, msg := range r.DNS.Warnings {
		printStatus(w, "WARN", msg)
	}
	for _, msg := range r.DNS.Failures {
		printStatus(w, "FAIL", msg)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Result Exit Code: %d\n", r.ExitCode)
}

func printStatus(w io.Writer, level string, msg string) {
	fmt.Fprintf(w, "[%s] %s\n", level, msg)
}
