package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

var (
	cfg          *config.Config
	auditStore   *audit.Store
	auditLog     *audit.Logger
	otelProvider *telemetry.Provider
	appVersion   string
)

func SetVersion(v string) {
	appVersion = v
	rootCmd.Version = v
}

func SetBuildInfo(commit, date string) {
	rootCmd.SetVersionTemplate(
		fmt.Sprintf("{{.Name}} version {{.Version}} (commit=%s, built=%s)\n", commit, date),
	)
}

var rootCmd = &cobra.Command{
	Use:   "defenseclaw-gateway",
	Short: "DefenseClaw gateway sidecar daemon",
	Long: `DefenseClaw gateway sidecar — connects to the OpenClaw gateway WebSocket,
monitors tool_call and tool_result events, enforces policy in real time,
and exposes a local REST API for the Python CLI.

Run without arguments to start the sidecar daemon.`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		var err error
		cfg, err = config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config — run 'defenseclaw init' first: %w", err)
		}

		auditStore, err = audit.NewStore(cfg.AuditDB)
		if err != nil {
			return fmt.Errorf("failed to open audit store: %w", err)
		}

		auditLog = audit.NewLogger(auditStore)
		initSplunkForwarder()
		initOTelProvider()
		return nil
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {
		if otelProvider != nil {
			if err := otelProvider.Shutdown(context.Background()); err != nil {
				fmt.Fprintf(os.Stderr, "warning: otel shutdown: %v\n", err)
			}
		}
		if auditLog != nil {
			auditLog.Close()
		}
		if auditStore != nil {
			auditStore.Close()
		}
	},
	RunE:         runSidecar,
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initOTelProvider() {
	if cfg == nil || !cfg.OTel.Enabled {
		return
	}

	p, err := telemetry.NewProvider(context.Background(), cfg, appVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: otel init: %v\n", err)
		return
	}

	otelProvider = p
	auditLog.SetOTelProvider(p)
}

func initSplunkForwarder() {
	if cfg == nil || !cfg.Splunk.Enabled {
		return
	}

	token := cfg.Splunk.HECToken
	if token == "" {
		token = os.Getenv("DEFENSECLAW_SPLUNK_HEC_TOKEN")
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "warning: splunk.enabled=true but no HEC token configured")
		return
	}

	splunkCfg := audit.SplunkConfig{
		HECEndpoint:   cfg.Splunk.HECEndpoint,
		HECToken:      token,
		Index:         cfg.Splunk.Index,
		Source:        cfg.Splunk.Source,
		SourceType:    cfg.Splunk.SourceType,
		VerifyTLS:     cfg.Splunk.VerifyTLS,
		Enabled:       true,
		BatchSize:     cfg.Splunk.BatchSize,
		FlushInterval: cfg.Splunk.FlushInterval,
	}

	fwd, err := audit.NewSplunkForwarder(splunkCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: splunk init: %v\n", err)
		return
	}

	auditLog.SetSplunkForwarder(fwd)
}
