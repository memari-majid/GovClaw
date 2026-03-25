package telemetry

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func disabledCfg() *config.Config {
	return &config.Config{
		OTel: config.OTelConfig{
			Enabled: false,
		},
		Claw: config.ClawConfig{
			Mode:    config.ClawOpenClaw,
			HomeDir: "/tmp/test-claw",
		},
		Gateway: config.GatewayConfig{
			Host: "127.0.0.1",
			Port: 18789,
		},
		Environment: "test",
	}
}

func TestNewProvider_Disabled(t *testing.T) {
	p, err := NewProvider(context.Background(), disabledCfg(), "test")
	if err != nil {
		t.Fatalf("NewProvider disabled: %v", err)
	}
	if p.Enabled() {
		t.Error("expected disabled provider")
	}
	if p.LogsEnabled() {
		t.Error("expected logs disabled")
	}
	if p.TracesEnabled() {
		t.Error("expected traces disabled")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("shutdown disabled: %v", err)
	}
}

func TestNewProvider_NilSafe(t *testing.T) {
	var p *Provider

	if p.Enabled() {
		t.Error("nil provider should not be enabled")
	}
	if p.LogsEnabled() {
		t.Error("nil provider logs should not be enabled")
	}
	if p.TracesEnabled() {
		t.Error("nil provider traces should not be enabled")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("nil shutdown: %v", err)
	}
}

func TestDisabledProvider_EmitLifecycleEvent_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.EmitLifecycleEvent("block", "test-skill", "skill", "test reason", "HIGH", nil)
}

func TestDisabledProvider_EmitScanResult_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	result := &scanner.ScanResult{
		Scanner:   "test-scanner",
		Target:    "/tmp/test",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
	}
	p.EmitScanResult(result, "scan-123", "skill", "clean")
}

func TestDisabledProvider_EmitRuntimeAlert_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.EmitRuntimeAlert(AlertDangerousCommand, "HIGH", SourceLocalPattern,
		"test alert", nil, nil, "", "")
}

func TestDisabledProvider_StartToolSpan_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	ctx, span := p.StartToolSpan(context.Background(), "shell", "running",
		json.RawMessage(`{"cmd":"ls"}`), false, "", "builtin", "")
	if span != nil {
		t.Error("span should be nil when disabled")
	}
	if ctx == nil {
		t.Error("context should not be nil")
	}
}

func TestDisabledProvider_Metrics_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	ctx := context.Background()
	p.RecordScan(ctx, "test", "skill", "clean", 100, map[string]int{"HIGH": 1})
	p.RecordToolCall(ctx, "shell", "builtin", false)
	p.RecordToolDuration(ctx, "shell", "builtin", 50)
	p.RecordToolError(ctx, "shell", 1)
	p.RecordApproval(ctx, "approved", true, false)
	p.RecordLLMCall(ctx, "openai", "gpt-4")
	p.RecordLLMTokens(ctx, "openai", 100, 200)
	p.RecordLLMDuration(ctx, "openai", "gpt-4", 500)
	p.RecordAlert(ctx, "dangerous-command", "HIGH", "local-pattern")
	p.RecordGuardrailEvaluation(ctx, "ai-defense", "block")
	p.RecordGuardrailLatency(ctx, "ai-defense", 100)
}

func TestExpandHeaders(t *testing.T) {
	t.Setenv("TEST_TOKEN", "abc123")

	headers := map[string]string{
		"X-SF-TOKEN":  "${TEST_TOKEN}",
		"X-Static":    "static-value",
	}

	expanded := expandHeaders(headers)
	if expanded["X-SF-TOKEN"] != "abc123" {
		t.Errorf("expected abc123, got %s", expanded["X-SF-TOKEN"])
	}
	if expanded["X-Static"] != "static-value" {
		t.Errorf("expected static-value, got %s", expanded["X-Static"])
	}
}

func TestExpandHeaders_MissingEnv(t *testing.T) {
	headers := map[string]string{
		"X-TOKEN": "${NONEXISTENT_VAR_12345}",
	}
	expanded := expandHeaders(headers)
	if expanded["X-TOKEN"] != "" {
		t.Errorf("expected empty for missing env, got %q", expanded["X-TOKEN"])
	}
}

func TestBuildSampler(t *testing.T) {
	tests := []struct {
		name string
		arg  string
	}{
		{"always_on", ""},
		{"always_off", ""},
		{"parentbased_traceidratio", "0.5"},
		{"parentbased_traceidratio", "invalid"},
		{"unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := buildSampler(tt.name, tt.arg)
			if s == nil {
				t.Error("sampler should not be nil")
			}
		})
	}
}

func TestActionMapping(t *testing.T) {
	tests := []struct {
		action         string
		wantLifecycle  string
		wantActor      string
	}{
		{"install-detected", "install", "watcher"},
		{"install-rejected", "block", "watcher"},
		{"install-allowed", "allow", "watcher"},
		{"install-clean", "install", "watcher"},
		{"install-warning", "install", "watcher"},
		{"install-scan-error", "scan-error", "watcher"},
		{"block", "block", "user"},
		{"watcher-block", "block", "watcher"},
		{"allow", "allow", "user"},
		{"quarantine", "quarantine", "defenseclaw"},
		{"restore", "restore", "user"},
		{"deploy", "install", "user"},
		{"stop", "uninstall", "user"},
		{"disable", "disable", "defenseclaw"},
		{"enable", "enable", "user"},
		{"api-skill-disable", "disable", "user"},
		{"api-skill-enable", "enable", "user"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			m, ok := actionMap[tt.action]
			if !ok {
				t.Fatalf("action %q not in actionMap", tt.action)
			}
			if m.LifecycleAction != tt.wantLifecycle {
				t.Errorf("lifecycle: got %s, want %s", m.LifecycleAction, tt.wantLifecycle)
			}
			if m.Actor != tt.wantActor {
				t.Errorf("actor: got %s, want %s", m.Actor, tt.wantActor)
			}
		})
	}
}

func TestNonLifecycleActionsExcluded(t *testing.T) {
	nonLifecycle := []string{
		"sidecar-start", "sidecar-stop", "sidecar-connected",
		"gateway-tool-call", "gateway-tool-result",
		"gateway-approval-requested", "watch-start", "watch-stop",
		"api-config-patch",
	}
	for _, action := range nonLifecycle {
		if _, ok := actionMap[action]; ok {
			t.Errorf("operational action %q should not be in lifecycle actionMap", action)
		}
	}
}

func TestSeverityMapping(t *testing.T) {
	tests := []struct {
		input   string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "ERROR", 17},
		{"ERROR", "ERROR", 17},
		{"HIGH", "WARN", 13},
		{"WARN", "WARN", 13},
		{"INFO", "INFO", 9},
		{"LOW", "INFO", 9},
		{"MEDIUM", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := severityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %s, want %s", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is to…"},
		{"", 5, ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := truncateStr(tt.input, tt.max); got != tt.want {
				t.Errorf("truncateStr(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
			}
		})
	}
}

func TestBaseCommand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"curl http://example.com", "curl"},
		{"/usr/bin/bash -c echo hello", "bash"},
		{"", ""},
		{"  git status  ", "git"},
		{"npm", "npm"},
		{"/usr/local/bin/python3 script.py", "python3"},
		{"./relative/path/to/binary --flag", "binary"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := baseCommand(tt.input); got != tt.want {
				t.Errorf("baseCommand(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildScanBody_ExcludesSensitiveFields(t *testing.T) {
	result := &scanner.ScanResult{
		Scanner:   "codeguard",
		Target:    "/path/to/project",
		Timestamp: time.Now(),
		Duration:  200 * time.Millisecond,
		Findings: []scanner.Finding{
			{
				ID:          "f1",
				Severity:    scanner.SeverityHigh,
				Title:       "Hardcoded secret",
				Description: "Found AWS key AKIA... in source",
				Location:    "/path/to/project/src/config.go:42",
				Remediation: "Use environment variables instead",
				Scanner:     "codeguard",
				Tags:        []string{"secrets", "aws"},
			},
		},
	}

	body := buildScanBody(result, "scan-001", "code")

	if len(body.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(body.Findings))
	}
	f := body.Findings[0]

	if f.ID != "f1" {
		t.Errorf("ID: got %q, want %q", f.ID, "f1")
	}
	if f.Severity != "HIGH" {
		t.Errorf("Severity: got %q, want %q", f.Severity, "HIGH")
	}
	if f.Title != "Hardcoded secret" {
		t.Errorf("Title: got %q, want %q", f.Title, "Hardcoded secret")
	}
	if f.Scanner != "codeguard" {
		t.Errorf("Scanner: got %q, want %q", f.Scanner, "codeguard")
	}
	if len(f.Tags) != 2 || f.Tags[0] != "secrets" {
		t.Errorf("Tags: got %v, want [secrets aws]", f.Tags)
	}

	bodyJSON, _ := json.Marshal(body)
	bodyStr := string(bodyJSON)
	for _, sensitive := range []string{"AKIA", "config.go:42", "environment variables"} {
		if containsStr(bodyStr, sensitive) {
			t.Errorf("scan body should not contain sensitive content %q", sensitive)
		}
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDeviceFingerprint_MissingFile(t *testing.T) {
	fp := deviceFingerprint("/nonexistent/path/to/key")
	if fp != "" {
		t.Errorf("expected empty fingerprint for missing file, got %q", fp)
	}
}

func TestDeviceFingerprint_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.key"
	if err := os.WriteFile(path, []byte("not a PEM file"), 0600); err != nil {
		t.Fatal(err)
	}
	fp := deviceFingerprint(path)
	if fp != "" {
		t.Errorf("expected empty fingerprint for invalid PEM, got %q", fp)
	}
}

func TestDeviceFingerprint_WrongSeedSize(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/wrong.key"
	pemData := "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(pemData), 0600); err != nil {
		t.Fatal(err)
	}
	fp := deviceFingerprint(path)
	if fp != "" {
		t.Errorf("expected empty fingerprint for wrong seed size, got %q", fp)
	}
}

func TestDeviceFingerprint_ValidKey(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/device.key"

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: seed})
	if err := os.WriteFile(path, pemBlock, 0600); err != nil {
		t.Fatal(err)
	}

	fp := deviceFingerprint(path)
	if fp == "" {
		t.Fatal("expected non-empty fingerprint for valid key")
	}
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars: %s", len(fp), fp)
	}

	fp2 := deviceFingerprint(path)
	if fp != fp2 {
		t.Errorf("fingerprint not deterministic: %s != %s", fp, fp2)
	}
}

func TestScanSeverityToOTel(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "ERROR", 17},
		{"HIGH", "WARN", 13},
		{"MEDIUM", "INFO", 9},
		{"LOW", "INFO", 9},
		{"", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := scanSeverityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestFindingSeverityToOTel(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "CRITICAL", 21},
		{"HIGH", "HIGH", 17},
		{"MEDIUM", "MEDIUM", 13},
		{"LOW", "LOW", 9},
		{"INFO", "INFO", 9},
		{"", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := findingSeverityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestAlertSeverityToOTel(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "CRITICAL", 21},
		{"HIGH", "HIGH", 17},
		{"MEDIUM", "MEDIUM", 13},
		{"LOW", "LOW", 9},
		{"unknown", "LOW", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := alertSeverityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestBuildResource(t *testing.T) {
	cfg := disabledCfg()
	cfg.OTel.Resource.Attributes = map[string]string{
		"custom.attr": "custom-value",
	}
	res := buildResource(cfg, "1.0.0-test")
	if res == nil {
		t.Fatal("resource should not be nil")
	}
}

// ---------------------------------------------------------------------------
// OTel metric verification tests — ensure guardrail metrics are actually
// recorded with the correct instruments and attribute values.
// ---------------------------------------------------------------------------

func TestRecordGuardrailEvaluation_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordGuardrailEvaluation(ctx, "litellm-guardrail", "block")
	p.RecordGuardrailEvaluation(ctx, "litellm-guardrail", "allow")
	p.RecordGuardrailEvaluation(ctx, "litellm-guardrail", "block")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findCounter(rm, "defenseclaw.guardrail.evaluations")
	if found == nil {
		t.Fatal("metric defenseclaw.guardrail.evaluations not found")
	}

	sum, ok := found.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected Sum[int64], got %T", found.Data)
	}

	blockCount := counterValueByAttr(sum, "guardrail.action_taken", "block")
	allowCount := counterValueByAttr(sum, "guardrail.action_taken", "allow")

	if blockCount != 2 {
		t.Errorf("block count = %d, want 2", blockCount)
	}
	if allowCount != 1 {
		t.Errorf("allow count = %d, want 1", allowCount)
	}
}

func TestRecordGuardrailLatency_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordGuardrailLatency(ctx, "litellm-guardrail", 15.5)
	p.RecordGuardrailLatency(ctx, "litellm-guardrail", 22.0)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findHistogram(rm, "defenseclaw.guardrail.latency")
	if found == nil {
		t.Fatal("metric defenseclaw.guardrail.latency not found")
	}

	hist, ok := found.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", found.Data)
	}

	if len(hist.DataPoints) == 0 {
		t.Fatal("expected at least one histogram data point")
	}

	dp := hist.DataPoints[0]
	if dp.Count != 2 {
		t.Errorf("histogram count = %d, want 2", dp.Count)
	}
	if dp.Sum != 37.5 {
		t.Errorf("histogram sum = %f, want 37.5", dp.Sum)
	}

	hasScanner := hasAttribute(dp.Attributes, "guardrail.scanner", "litellm-guardrail")
	if !hasScanner {
		t.Error("histogram missing attribute guardrail.scanner=litellm-guardrail")
	}
}

func TestRecordLLMTokens_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordLLMTokens(ctx, "litellm", 150, 75)
	p.RecordLLMTokens(ctx, "litellm", 200, 0) // no completion tokens

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findCounter(rm, "defenseclaw.llm.tokens")
	if found == nil {
		t.Fatal("metric defenseclaw.llm.tokens not found")
	}

	sum, ok := found.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected Sum[int64], got %T", found.Data)
	}

	promptTokens := counterValueByAttr(sum, "token.type", "prompt")
	completionTokens := counterValueByAttr(sum, "token.type", "completion")

	if promptTokens != 350 {
		t.Errorf("prompt tokens = %d, want 350", promptTokens)
	}
	if completionTokens != 75 {
		t.Errorf("completion tokens = %d, want 75", completionTokens)
	}
}

func TestRecordGuardrailEvaluation_DisabledProvider_NoOp(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.RecordGuardrailEvaluation(context.Background(), "test", "block")
}

// ---------------------------------------------------------------------------
// Metric collection helpers
// ---------------------------------------------------------------------------

func findCounter(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

func findHistogram(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	return findCounter(rm, name) // same lookup, different data type
}

func counterValueByAttr(sum metricdata.Sum[int64], key, val string) int64 {
	for _, dp := range sum.DataPoints {
		if hasAttribute(dp.Attributes, key, val) {
			return dp.Value
		}
	}
	return 0
}

func hasAttribute(attrs attribute.Set, key, val string) bool {
	v, ok := attrs.Value(attribute.Key(key))
	return ok && v.AsString() == val
}
