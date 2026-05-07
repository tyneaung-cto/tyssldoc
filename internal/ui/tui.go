package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"tyssldoc/internal/report"
)

type FetchReportFn func() (*report.Report, error)

type reportMsg struct {
	report *report.Report
	err    error
}

type tickMsg time.Time

type Model struct {
	loading bool
	report  *report.Report
	err     error
	fetch   FetchReportFn
	frame   int
}

func NewModel(fetch FetchReportFn) *Model {
	return &Model{loading: true, fetch: fetch}
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(fetchCmd(m.fetch), tickCmd())
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		s := msg.String()
		if s == "q" || s == "ctrl+c" || s == "enter" {
			return m, tea.Quit
		}
	case tickMsg:
		if m.loading {
			m.frame = (m.frame + 1) % len(spinnerFrames)
			return m, tickCmd()
		}
	case reportMsg:
		m.loading = false
		m.report = msg.report
		m.err = msg.err
	}
	return m, nil
}

func (m *Model) View() string {
	if m.loading {
		spin := spinnerFrames[m.frame]
		line := fmt.Sprintf("%s Checking DNS, TLS, and HTTPS...", spin)
		return lipgloss.NewStyle().Padding(1, 2).Render(line) + "\n"
	}
	if m.err != nil {
		fail := badge("FAIL")
		return lipgloss.NewStyle().Padding(1, 2).Render(fmt.Sprintf("%s %v\nPress q to quit", fail, m.err)) + "\n"
	}
	return renderReport(m.report)
}

func (m *Model) Result() (*report.Report, error) { return m.report, m.err }

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func tickCmd() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func fetchCmd(fetch FetchReportFn) tea.Cmd {
	return func() tea.Msg {
		rep, err := fetch()
		return reportMsg{report: rep, err: err}
	}
}

func renderReport(r *report.Report) string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")).Render("tyssldoc SSL/TLS Report")
	target := lipgloss.NewStyle().Foreground(lipgloss.Color("7")).Render("Target: " + r.Target.HostPort)
	meta := lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("Checked: " + r.CheckedAt.Format(time.RFC3339))

	sections := []string{title, target, meta, "", renderTLS(r), "", renderHTTP(r), "", renderDNS(r), "", lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("Exit Code: %d", r.ExitCode)), lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("Press enter to continue, or q to quit")}
	box := lipgloss.NewStyle().Padding(1, 2).Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("8"))
	return box.Render(strings.Join(sections, "\n")) + "\n"
}

func renderTLS(r *report.Report) string {
	lines := []string{lipgloss.NewStyle().Bold(true).Render("TLS")}
	if r.TLS.Reachable {
		lines = append(lines, row("OK", "TLS handshake succeeded"))
	} else {
		lines = append(lines, row("FAIL", "TLS handshake failed"))
	}
	if r.TLS.ChainValid {
		lines = append(lines, row("OK", "Certificate chain trusted"))
	}
	if r.TLS.HostnameValid {
		lines = append(lines, row("OK", "Hostname matches certificate"))
	}
	if r.TLS.TLSVersion != "" {
		lines = append(lines, row("INFO", "Version: "+r.TLS.TLSVersion))
	}
	if r.TLS.CipherSuite != "" {
		lines = append(lines, row("INFO", "Cipher: "+r.TLS.CipherSuite))
	}
	if r.TLS.HandshakeTime != "" {
		lines = append(lines, row("INFO", "Handshake: "+r.TLS.HandshakeTime))
	}
	for _, w := range r.TLS.Warnings {
		lines = append(lines, row("WARN", w))
	}
	for _, f := range r.TLS.Failures {
		lines = append(lines, row("FAIL", f))
	}
	if r.TLS.Cert != nil {
		lines = append(lines, row("INFO", "Subject: "+r.TLS.Cert.Subject))
		lines = append(lines, row("INFO", "Issuer: "+r.TLS.Cert.Issuer))
		lines = append(lines, row("INFO", fmt.Sprintf("Days Remaining: %d", r.TLS.Cert.DaysRemaining)))
	}
	return strings.Join(lines, "\n")
}

func renderHTTP(r *report.Report) string {
	lines := []string{lipgloss.NewStyle().Bold(true).Render("HTTP")}
	if r.HTTP.HTTPSReachable {
		lines = append(lines, row("OK", fmt.Sprintf("HTTPS reachable (%d)", r.HTTP.HTTPSStatusCode)))
	} else {
		lines = append(lines, row("FAIL", "HTTPS unreachable"))
	}
	if r.HTTP.HTTPRedirectsHTTPS {
		lines = append(lines, row("OK", "HTTP redirects to HTTPS"))
	} else {
		lines = append(lines, row("WARN", "HTTP does not redirect to HTTPS"))
	}
	if r.HTTP.HSTS != "" {
		lines = append(lines, row("OK", "HSTS enabled"))
	} else {
		lines = append(lines, row("WARN", "HSTS missing"))
	}
	if r.HTTP.FinalURL != "" {
		lines = append(lines, row("INFO", "Final URL: "+r.HTTP.FinalURL))
	}
	for _, w := range r.HTTP.Warnings {
		lines = append(lines, row("WARN", w))
	}
	for _, f := range r.HTTP.Failures {
		lines = append(lines, row("FAIL", f))
	}
	keys := make([]string, 0, len(r.HTTP.SecurityHeaders))
	for k := range r.HTTP.SecurityHeaders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := r.HTTP.SecurityHeaders[k]
		if v == "" {
			v = "(missing)"
		}
		lines = append(lines, row("INFO", fmt.Sprintf("%s: %s", k, v)))
	}
	return strings.Join(lines, "\n")
}

func renderDNS(r *report.Report) string {
	lines := []string{lipgloss.NewStyle().Bold(true).Render("DNS")}
	if len(r.DNS.ARecords) > 0 {
		lines = append(lines, row("INFO", "A: "+strings.Join(r.DNS.ARecords, ", ")))
	} else {
		lines = append(lines, row("WARN", "A records missing"))
	}
	if len(r.DNS.AAAARecords) > 0 {
		lines = append(lines, row("INFO", "AAAA: "+strings.Join(r.DNS.AAAARecords, ", ")))
	} else {
		lines = append(lines, row("WARN", "AAAA records missing"))
	}
	if r.DNS.CNAME != "" {
		lines = append(lines, row("INFO", "CNAME: "+r.DNS.CNAME))
	}
	for _, w := range r.DNS.Warnings {
		lines = append(lines, row("WARN", w))
	}
	for _, f := range r.DNS.Failures {
		lines = append(lines, row("FAIL", f))
	}
	return strings.Join(lines, "\n")
}

func row(level, message string) string { return fmt.Sprintf("%s %s", badge(level), message) }

func badge(level string) string {
	base := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	switch level {
	case "OK":
		return base.Background(lipgloss.Color("2")).Foreground(lipgloss.Color("0")).Render("OK")
	case "WARN":
		return base.Background(lipgloss.Color("3")).Foreground(lipgloss.Color("0")).Render("WARN")
	case "FAIL":
		return base.Background(lipgloss.Color("1")).Foreground(lipgloss.Color("15")).Render("FAIL")
	default:
		return base.Background(lipgloss.Color("7")).Foreground(lipgloss.Color("0")).Render("INFO")
	}
}
