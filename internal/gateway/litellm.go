package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// LiteLLMProcess manages the LiteLLM proxy as a child process of the sidecar.
// It starts litellm with the generated config, monitors health, and restarts
// on crash. The guardrail Python module directory is added to PYTHONPATH so
// LiteLLM can import it.
type LiteLLMProcess struct {
	cfg     *config.GuardrailConfig
	logger  *audit.Logger
	health  *SidecarHealth
	apiPort int
}

func NewLiteLLMProcess(cfg *config.GuardrailConfig, logger *audit.Logger, health *SidecarHealth, apiPort int) *LiteLLMProcess {
	return &LiteLLMProcess{cfg: cfg, logger: logger, health: health, apiPort: apiPort}
}

// Run starts the LiteLLM proxy and keeps it running until ctx is cancelled.
// If the process exits unexpectedly, it is restarted with exponential backoff.
func (l *LiteLLMProcess) Run(ctx context.Context) error {
	if !l.cfg.Enabled {
		l.health.SetGuardrail(StateDisabled, "", nil)
		fmt.Fprintf(os.Stderr, "[guardrail] disabled (enable via: defenseclaw setup guardrail)\n")
		<-ctx.Done()
		return nil
	}

	binary, err := l.findBinary()
	if err != nil {
		l.health.SetGuardrail(StateError, err.Error(), nil)
		fmt.Fprintf(os.Stderr, "[guardrail] %v\n", err)
		<-ctx.Done()
		return err
	}

	if _, err := os.Stat(l.cfg.LiteLLMConfig); os.IsNotExist(err) {
		msg := fmt.Sprintf("litellm config not found: %s (run: defenseclaw setup guardrail)", l.cfg.LiteLLMConfig)
		l.health.SetGuardrail(StateError, msg, nil)
		fmt.Fprintf(os.Stderr, "[guardrail] %s\n", msg)
		<-ctx.Done()
		return fmt.Errorf("guardrail: %s", msg)
	}

	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		l.health.SetGuardrail(StateStarting, "", map[string]interface{}{
			"port":   l.cfg.Port,
			"mode":   l.cfg.Mode,
			"config": l.cfg.LiteLLMConfig,
		})

		fmt.Fprintf(os.Stderr, "[guardrail] starting LiteLLM (port=%d mode=%s)\n", l.cfg.Port, l.cfg.Mode)
		_ = l.logger.LogAction("guardrail-start", "", fmt.Sprintf("port=%d mode=%s", l.cfg.Port, l.cfg.Mode))

		exitErr := l.runProcess(ctx, binary)

		if ctx.Err() != nil {
			l.health.SetGuardrail(StateStopped, "", nil)
			fmt.Fprintf(os.Stderr, "[guardrail] stopped\n")
			return nil
		}

		errMsg := ""
		if exitErr != nil {
			errMsg = exitErr.Error()
		}
		l.health.SetGuardrail(StateError, fmt.Sprintf("exited: %s", errMsg), nil)
		fmt.Fprintf(os.Stderr, "[guardrail] process exited (%v), restarting in %s...\n", exitErr, backoff)
		_ = l.logger.LogAction("guardrail-crash", "", fmt.Sprintf("exit=%v backoff=%s", exitErr, backoff))

		select {
		case <-ctx.Done():
			l.health.SetGuardrail(StateStopped, "", nil)
			return nil
		case <-time.After(backoff):
		}

		backoff = backoff * 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (l *LiteLLMProcess) runProcess(ctx context.Context, binary string) error {
	args := []string{
		"--config", l.cfg.LiteLLMConfig,
		"--port", fmt.Sprintf("%d", l.cfg.Port),
		"--detailed_debug",
	}

	cmd := exec.CommandContext(ctx, binary, args...)

	cmd.Env = l.buildEnv()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("guardrail: stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("guardrail: stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("guardrail: start: %w", err)
	}

	go l.streamLog("litellm:out", stdout)
	go l.streamLog("litellm:err", stderr)

	// Wait for LiteLLM to become healthy
	go l.waitForHealthy(ctx)

	return cmd.Wait()
}

func (l *LiteLLMProcess) buildEnv() []string {
	env := os.Environ()

	// Load ~/.defenseclaw/.env for daemon contexts where the user's
	// shell environment (and its API keys) aren't inherited.
	envFile := filepath.Join(filepath.Dir(l.cfg.LiteLLMConfig), ".env")
	if dotenv, err := loadDotEnv(envFile); err == nil {
		present := make(map[string]bool, len(env))
		for _, e := range env {
			if k, _, ok := strings.Cut(e, "="); ok {
				present[k] = true
			}
		}
		for k, v := range dotenv {
			if !present[k] {
				env = append(env, k+"="+v)
			}
		}
	}

	pythonPath := l.cfg.GuardrailDir
	for _, e := range env {
		if strings.HasPrefix(e, "PYTHONPATH=") {
			existing := strings.TrimPrefix(e, "PYTHONPATH=")
			pythonPath = l.cfg.GuardrailDir + string(filepath.ListSeparator) + existing
			break
		}
	}

	// Vars we set explicitly — filter out any inherited copies to avoid
	// duplicates (last-writer-wins is OS-dependent).
	overridden := map[string]bool{
		"PYTHONPATH":                  true,
		"DEFENSECLAW_GUARDRAIL_MODE":  true,
		"DEFENSECLAW_SCANNER_MODE":    true,
		"DEFENSECLAW_API_PORT":        true,
	}
	filtered := make([]string, 0, len(env)+6)
	for _, e := range env {
		if k, _, ok := strings.Cut(e, "="); ok && overridden[k] {
			continue
		}
		filtered = append(filtered, e)
	}
	filtered = append(filtered, "PYTHONPATH="+pythonPath)
	filtered = append(filtered, "DEFENSECLAW_GUARDRAIL_MODE="+l.cfg.Mode)
	if l.cfg.ScannerMode != "" {
		filtered = append(filtered, "DEFENSECLAW_SCANNER_MODE="+l.cfg.ScannerMode)
	}
	if l.apiPort > 0 {
		filtered = append(filtered, fmt.Sprintf("DEFENSECLAW_API_PORT=%d", l.apiPort))
	}

	if l.cfg.ScannerMode == "remote" || l.cfg.ScannerMode == "both" {
		if l.cfg.CiscoAIDefense.Endpoint != "" {
			filtered = append(filtered, "CISCO_AI_DEFENSE_ENDPOINT="+l.cfg.CiscoAIDefense.Endpoint)
		}
		if l.cfg.CiscoAIDefense.APIKeyEnv != "" {
			filtered = append(filtered, "CISCO_AI_DEFENSE_API_KEY_ENV="+l.cfg.CiscoAIDefense.APIKeyEnv)
		}
		if l.cfg.CiscoAIDefense.TimeoutMs > 0 {
			filtered = append(filtered, fmt.Sprintf("CISCO_AI_DEFENSE_TIMEOUT_MS=%d", l.cfg.CiscoAIDefense.TimeoutMs))
		}
		if len(l.cfg.CiscoAIDefense.EnabledRules) > 0 {
			filtered = append(filtered, "CISCO_AI_DEFENSE_ENABLED_RULES="+strings.Join(l.cfg.CiscoAIDefense.EnabledRules, ","))
		}
	}

	return filtered
}

func (l *LiteLLMProcess) streamLog(prefix string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintf(os.Stderr, "[%s] %s\n", prefix, line)
	}
}

func (l *LiteLLMProcess) waitForHealthy(ctx context.Context) {
	client := &http.Client{Timeout: 2 * time.Second}
	addr := fmt.Sprintf("http://127.0.0.1:%d/health/liveliness", l.cfg.Port)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	deadline := time.After(30 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			l.health.SetGuardrail(StateError, "health check timed out after 30s", nil)
			fmt.Fprintf(os.Stderr, "[guardrail] health check timed out\n")
			return
		case <-ticker.C:
			resp, err := client.Get(addr)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				l.health.SetGuardrail(StateRunning, "", map[string]interface{}{
					"port": l.cfg.Port,
					"mode": l.cfg.Mode,
				})
				fmt.Fprintf(os.Stderr, "[guardrail] LiteLLM healthy on port %d\n", l.cfg.Port)
				_ = l.logger.LogAction("guardrail-healthy", "", fmt.Sprintf("port=%d", l.cfg.Port))
				return
			}
		}
	}
}

func (l *LiteLLMProcess) findBinary() (string, error) {
	path, err := exec.LookPath("litellm")
	if err == nil {
		return path, nil
	}

	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".local", "bin", "litellm"),
		filepath.Join(home, ".cargo", "bin", "litellm"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf("litellm binary not found — install with: uv tool install 'litellm[proxy]'")
}

// loadDotEnv reads a KEY=VALUE file (one per line).  Blank lines and
// lines starting with # are ignored.  Values may be optionally quoted.
// This lets the sidecar pick up API keys when running as a daemon
// (where the user's shell env isn't inherited).
func loadDotEnv(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		if k != "" {
			out[k] = v
		}
	}
	return out, nil
}
