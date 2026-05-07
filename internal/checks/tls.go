package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

func RunTLSChecks(ctx context.Context, target Target, timeout time.Duration, insecure bool) TLSResult {
	result := TLSResult{
		ServerName:       target.Host,
		UsedInsecureMode: insecure,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conf := &tls.Config{ServerName: target.Host, InsecureSkipVerify: insecure} //nolint:gosec

	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", target.HostPort, conf)
	if err != nil {
		result.Failures = append(result.Failures, "TLS handshake failed: "+err.Error())
		return result
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		result.Warnings = append(result.Warnings, "failed to set connection deadline: "+err.Error())
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		result.Failures = append(result.Failures, "TLS handshake context failed: "+err.Error())
		return result
	}

	result.Reachable = true
	result.HandshakeTime = time.Since(start).Round(time.Millisecond).String()

	state := conn.ConnectionState()
	result.TLSVersion = tls.VersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.ALPN = state.NegotiatedProtocol

	if len(state.PeerCertificates) == 0 {
		result.Failures = append(result.Failures, "server did not present certificates")
		return result
	}

	leaf := state.PeerCertificates[0]
	result.Cert = summarizeCert(leaf)

	for _, cert := range state.PeerCertificates {
		result.Chain = append(result.Chain, ChainCertificate{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.Text(16),
			NotAfter:     cert.NotAfter.Format(time.RFC3339),
		})
	}

	if err := leaf.VerifyHostname(target.Host); err != nil {
		result.Failures = append(result.Failures, "hostname mismatch: "+err.Error())
		result.HostnameValid = false
	} else {
		result.HostnameValid = true
	}

	now := time.Now()
	if now.Before(leaf.NotBefore) {
		result.Failures = append(result.Failures, "certificate is not yet valid")
	}
	if now.After(leaf.NotAfter) {
		result.Failures = append(result.Failures, "certificate has expired")
	} else if daysRemaining(leaf.NotAfter) <= 30 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("certificate expires in %d days", daysRemaining(leaf.NotAfter)))
	}

	if insecure {
		if len(state.VerifiedChains) > 0 {
			result.ChainValid = true
		} else {
			roots, err := x509.SystemCertPool()
			if err != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			intermediates := x509.NewCertPool()
			for _, c := range state.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			_, verifyErr := leaf.Verify(x509.VerifyOptions{
				DNSName:       target.Host,
				Intermediates: intermediates,
				Roots:         roots,
				CurrentTime:   now,
			})
			if verifyErr != nil {
				result.ChainValid = false
				result.VerificationErrors = append(result.VerificationErrors, verifyErr.Error())
				result.Failures = append(result.Failures, "certificate chain validation failed")
			} else {
				result.ChainValid = true
			}
		}
	} else {
		result.ChainValid = true
	}

	if result.ALPN == "" {
		result.Info = append(result.Info, "ALPN protocol not negotiated")
	}

	return result
}

func summarizeCert(cert *x509.Certificate) *CertificateSummary {
	return &CertificateSummary{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SerialNumber:  cert.SerialNumber.Text(16),
		NotBefore:     cert.NotBefore.Format(time.RFC3339),
		NotAfter:      cert.NotAfter.Format(time.RFC3339),
		DaysRemaining: daysRemaining(cert.NotAfter),
		SANs:          cert.DNSNames,
	}
}
