package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"tyssldoc/internal/checks"
	"tyssldoc/internal/report"
	"tyssldoc/internal/ui"
)

var version = "dev"
var commit = "none"
var date = "unknown"

const about = "Author: Phyo Wai Yan\nGitHub: https://github.com/phyowaiyan\nProject: https://github.com/phyowaiyan/tyssldoc"

type cliError struct {
	code int
	err  error
}

func (e cliError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func main() {
	if code := run(); code != 0 {
		os.Exit(code)
	}
}

func run() int {
	var (
		jsonMode bool
		timeout  time.Duration
		insecure bool
	)

	normalizedArgs := normalizeCLIArgs(os.Args)

	runAudit := func(domain string) (*report.Report, error) {
		target, err := checks.NormalizeTarget(domain)
		if err != nil {
			return nil, cliError{code: 2, err: fmt.Errorf("invalid target: %w", err)}
		}

		rep := &report.Report{Version: version + " (" + commit + ", " + date + ")", CheckedAt: time.Now().UTC(), Target: target}

		dnsCtx, dnsCancel := context.WithTimeout(context.Background(), timeout)
		rep.DNS = checks.RunDNSChecks(dnsCtx, target)
		dnsCancel()

		tlsCtx, tlsCancel := context.WithTimeout(context.Background(), timeout)
		rep.TLS = checks.RunTLSChecks(tlsCtx, target, timeout, insecure)
		tlsCancel()

		httpCtx, httpCancel := context.WithTimeout(context.Background(), timeout)
		rep.HTTP = checks.RunHTTPChecks(httpCtx, target, timeout)
		httpCancel()

		rep.ExitCode = report.DeriveExitCode(rep)
		return rep, nil
	}

	execStandard := func(cmd *cobra.Command, domain string) error {
		rep, err := runAudit(domain)
		if err != nil {
			return err
		}
		if jsonMode {
			if err := report.PrintJSON(cmd.OutOrStdout(), rep); err != nil {
				return cliError{code: 2, err: fmt.Errorf("failed to write JSON: %w", err)}
			}
			return cliError{code: rep.ExitCode}
		}
		report.PrintHuman(cmd.OutOrStdout(), rep)
		return cliError{code: rep.ExitCode}
	}

	execTUI := func(cmd *cobra.Command, domain string) error {
		if jsonMode {
			return cliError{code: 2, err: fmt.Errorf("--json cannot be used with tui command")}
		}
		m := ui.NewModel(func() (*report.Report, error) { return runAudit(domain) })
		p := tea.NewProgram(m)
		if _, err := p.Run(); err != nil {
			if rep, repErr := runAudit(domain); repErr == nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: interactive TUI unavailable, falling back to standard output")
				report.PrintHuman(cmd.OutOrStdout(), rep)
				return cliError{code: rep.ExitCode}
			}
			return cliError{code: 2, err: fmt.Errorf("failed to run TUI: %w", err)}
		}
		rep, err := m.Result()
		if err != nil {
			return err
		}
		if rep == nil {
			return cliError{code: 2, err: fmt.Errorf("no report generated")}
		}
		return cliError{code: rep.ExitCode}
	}

	runInteractiveLoop := func(cmd *cobra.Command) error {
		if jsonMode {
			return cliError{code: 2, err: fmt.Errorf("--json requires a domain argument")}
		}
		reader := bufio.NewReader(cmd.InOrStdin())
		for {
			domain, err := promptDomain(reader, cmd.OutOrStdout())
			if err != nil {
				return cliError{code: 2, err: err}
			}
			if err := execTUI(cmd, domain); err != nil {
				var ce cliError
				if errors.As(err, &ce) {
					fmt.Fprintf(cmd.OutOrStdout(), "\nScan finished with exit code %d.\n", ce.code)
				} else {
					return err
				}
			}
			again, err := promptYesNo(reader, cmd.OutOrStdout(), "Check another domain? (y/N): ")
			if err != nil {
				return cliError{code: 2, err: err}
			}
			if !again {
				fmt.Fprintln(cmd.OutOrStdout(), "Goodbye.")
				return nil
			}
		}
	}

	root := &cobra.Command{
		Use:           "tyssldoc [domain]",
		Short:         "Remote SSL/TLS diagnostic tool",
		Long:          "tyssldoc checks TLS certificates, HTTPS behavior, and DNS records for a domain.\n\n" + about,
		Example:       "  tyssldoc example.com\n  tyssldoc tui example.com\n  tyssldoc --timeout 15s example.com\n  tyssldoc",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return runInteractiveLoop(cmd)
			}
			return execStandard(cmd, args[0])
		},
	}

	checkCmd := &cobra.Command{Use: "check <domain>", Short: "Run SSL/TLS checks for a target domain", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return execStandard(cmd, args[0]) }}
	tuiCmd := &cobra.Command{Use: "tui <domain>", Short: "Run checks in an interactive terminal UI", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return execTUI(cmd, args[0]) }}
	aboutCmd := &cobra.Command{Use: "about", Short: "Show author and project links", Run: func(cmd *cobra.Command, _ []string) { fmt.Fprintln(cmd.OutOrStdout(), about) }}

	root.AddCommand(checkCmd, tuiCmd, aboutCmd)
	root.Version = version
	root.Annotations = map[string]string{"commit": commit, "date": date}
	root.SetVersionTemplate("tyssldoc {{.Version}}\ncommit: {{.Annotations.commit}}\nbuild date: {{.Annotations.date}}\n")

	root.PersistentFlags().BoolVar(&jsonMode, "json", false, "output report as JSON (domain mode only)")
	root.PersistentFlags().DurationVar(&timeout, "timeout", 10*time.Second, "network timeout per check (e.g. 10s)")
	root.PersistentFlags().BoolVar(&insecure, "insecure", false, "collect certificate details even when validation fails")
	root.SetArgs(normalizedArgs)

	if err := root.Execute(); err != nil {
		var ce cliError
		if errors.As(err, &ce) {
			if ce.err != nil {
				fmt.Fprintln(os.Stderr, ce.err)
			}
			return ce.code
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

func promptDomain(reader *bufio.Reader, out io.Writer) (string, error) {
	for {
		fmt.Fprint(out, "Enter domain (example.com or https://example.com): ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read domain: %w", err)
		}
		domain := strings.TrimSpace(line)
		if domain == "" {
			fmt.Fprintln(out, "Domain is required.")
			continue
		}
		if _, err := checks.NormalizeTarget(domain); err != nil {
			fmt.Fprintf(out, "Invalid domain: %v\n", err)
			continue
		}
		return domain, nil
	}
}

func promptYesNo(reader *bufio.Reader, out io.Writer, question string) (bool, error) {
	fmt.Fprint(out, question)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read input: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func normalizeCLIArgs(args []string) []string {
	if len(args) < 3 {
		if len(args) > 1 {
			return args[1:]
		}
		return nil
	}
	cmdName := strings.ToLower(strings.TrimSuffix(args[0], ".exe"))
	cmdName = strings.TrimPrefix(cmdName, "./")
	dup := strings.ToLower(args[1])
	if strings.HasSuffix(cmdName, "tyssldoc") && dup == "tyssldoc" {
		return args[2:]
	}
	return args[1:]
}
