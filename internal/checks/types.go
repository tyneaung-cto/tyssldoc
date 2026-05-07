package checks

import "time"

type Target struct {
	Raw      string `json:"raw"`
	Input    string `json:"input"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	HostPort string `json:"host_port"`
}

type DNSResult struct {
	ARecords    []string `json:"a_records"`
	AAAARecords []string `json:"aaaa_records"`
	CNAME       string   `json:"cname,omitempty"`
	Warnings    []string `json:"warnings"`
	Failures    []string `json:"failures"`
}

type CertificateSummary struct {
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	SerialNumber  string   `json:"serial_number"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
	DaysRemaining int      `json:"days_remaining"`
	SANs          []string `json:"san_dns_names"`
}

type ChainCertificate struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serial_number"`
	NotAfter     string `json:"not_after"`
}

type TLSResult struct {
	Reachable          bool                `json:"reachable"`
	ServerName         string              `json:"server_name"`
	TLSVersion         string              `json:"tls_version,omitempty"`
	CipherSuite        string              `json:"cipher_suite,omitempty"`
	ALPN               string              `json:"alpn,omitempty"`
	HandshakeTime      string              `json:"handshake_time,omitempty"`
	Cert               *CertificateSummary `json:"certificate,omitempty"`
	Chain              []ChainCertificate  `json:"chain"`
	HostnameValid      bool                `json:"hostname_valid"`
	ChainValid         bool                `json:"chain_valid"`
	UsedInsecureMode   bool                `json:"used_insecure_mode"`
	Warnings           []string            `json:"warnings"`
	Failures           []string            `json:"failures"`
	Info               []string            `json:"info"`
	VerificationErrors []string            `json:"verification_errors"`
}

type HTTPResult struct {
	HTTPSReachable     bool              `json:"https_reachable"`
	FinalURL           string            `json:"final_url,omitempty"`
	HTTPSStatusCode    int               `json:"https_status_code,omitempty"`
	HTTPRedirectsHTTPS bool              `json:"http_redirects_to_https"`
	HSTS               string            `json:"hsts,omitempty"`
	SecurityHeaders    map[string]string `json:"security_headers"`
	Warnings           []string          `json:"warnings"`
	Failures           []string          `json:"failures"`
	Info               []string          `json:"info"`
}

func daysRemaining(notAfter time.Time) int {
	return int(time.Until(notAfter).Hours() / 24)
}
