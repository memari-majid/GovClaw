package gateway

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// APIServer exposes a local REST API for CLI and plugin communication
// with the running sidecar.
type APIServer struct {
	health     *SidecarHealth
	client     *Client
	store      *audit.Store
	logger     *audit.Logger
	addr       string
	scannerCfg *config.Config
	otel       *telemetry.Provider
}

// SetOTelProvider attaches the OTel provider so guardrail events
// can be recorded as metrics.
func (a *APIServer) SetOTelProvider(p *telemetry.Provider) {
	a.otel = p
}

// NewAPIServer creates the REST API server bound to the given address.
func NewAPIServer(addr string, health *SidecarHealth, client *Client, store *audit.Store, logger *audit.Logger, cfg ...*config.Config) *APIServer {
	s := &APIServer{
		addr:   addr,
		health: health,
		client: client,
		store:  store,
		logger: logger,
	}
	if len(cfg) > 0 {
		s.scannerCfg = cfg[0]
	}
	return s
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (a *APIServer) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/status", a.handleStatus)
	mux.HandleFunc("/skill/disable", a.handleSkillDisable)
	mux.HandleFunc("/skill/enable", a.handleSkillEnable)
	mux.HandleFunc("/config/patch", a.handleConfigPatch)
	mux.HandleFunc("/scan/result", a.handleScanResult)
	mux.HandleFunc("/enforce/block", a.handleEnforceBlock)
	mux.HandleFunc("/enforce/allow", a.handleEnforceAllow)
	mux.HandleFunc("/enforce/blocked", a.handleEnforceBlocked)
	mux.HandleFunc("/enforce/allowed", a.handleEnforceAllowed)
	mux.HandleFunc("/alerts", a.handleAlerts)
	mux.HandleFunc("/audit/event", a.handleAuditEvent)
	mux.HandleFunc("/policy/evaluate", a.handlePolicyEvaluate)
	mux.HandleFunc("/skills", a.handleSkills)
	mux.HandleFunc("/mcps", a.handleMCPs)
	mux.HandleFunc("/tools/catalog", a.handleToolsCatalog)
	mux.HandleFunc("/v1/skill/scan", a.handleSkillScan)
	mux.HandleFunc("/v1/skill/fetch", a.handleSkillFetch)
	mux.HandleFunc("/v1/guardrail/event", a.handleGuardrailEvent)
	mux.HandleFunc("/v1/guardrail/evaluate", a.handleGuardrailEvaluate)
	mux.HandleFunc("/v1/guardrail/config", a.handleGuardrailConfig)
	mux.HandleFunc("/api/v1/inspect/tool", a.handleInspectTool)

	srv := &http.Server{
		Addr:    a.addr,
		Handler: csrfProtect(mux),
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "[sidecar-api] listening on %s\n", a.addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	a.health.SetAPI(StateRunning, "", map[string]interface{}{"addr": a.addr})

	select {
	case err := <-errCh:
		a.health.SetAPI(StateError, err.Error(), nil)
		return fmt.Errorf("api: listen %s: %w", a.addr, err)
	case <-ctx.Done():
		a.health.SetAPI(StateStopped, "", nil)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func (a *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := a.health.Snapshot()
	a.writeJSON(w, http.StatusOK, snap)
}

func (a *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snap := a.health.Snapshot()

	status := map[string]interface{}{
		"health": snap,
	}

	if a.client != nil && a.client.Hello() != nil {
		hello := a.client.Hello()
		status["gateway_hello"] = hello
	}

	a.writeJSON(w, http.StatusOK, status)
}

type skillActionRequest struct {
	SkillKey string `json:"skillKey"`
}

func (a *APIServer) handleSkillDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.SkillKey == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "skillKey is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.client.DisableSkill(ctx, req.SkillKey); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogAction("api-skill-disable", req.SkillKey, "disabled via REST API")
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "disabled", "skillKey": req.SkillKey})
}

func (a *APIServer) handleSkillEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.SkillKey == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "skillKey is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.client.EnableSkill(ctx, req.SkillKey); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogAction("api-skill-enable", req.SkillKey, "enabled via REST API")
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "enabled", "skillKey": req.SkillKey})
}

type configPatchRequest struct {
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

type enforcementRequest struct {
	TargetType string `json:"target_type"`
	TargetName string `json:"target_name"`
	Reason     string `json:"reason"`
}

type enforcementEntry struct {
	ID         string    `json:"id"`
	TargetType string    `json:"target_type"`
	TargetName string    `json:"target_name"`
	Reason     string    `json:"reason"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type policyEvaluateRequest struct {
	Domain string              `json:"domain"`
	Input  policyEvaluateInput `json:"input"`
}

type policyEvaluateInput struct {
	TargetType string                    `json:"target_type"`
	TargetName string                    `json:"target_name"`
	Path       string                    `json:"path"`
	ScanResult *policyEvaluateScanResult `json:"scan_result,omitempty"`
}

type policyEvaluateScanResult struct {
	MaxSeverity   string `json:"max_severity"`
	TotalFindings int    `json:"total_findings"`
}

func (a *APIServer) handleConfigPatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req configPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Path == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.client.PatchConfig(ctx, req.Path, req.Value); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogAction("api-config-patch", req.Path, fmt.Sprintf("patched via REST API value_type=%T", req.Value))
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "patched", "path": req.Path})
}

func (a *APIServer) handleScanResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger := a.logger
	if logger == nil {
		if a.store == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
			return
		}
		logger = audit.NewLogger(a.store)
	}

	var result scanner.ScanResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if result.Scanner == "" || result.Target == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scanner and target are required"})
		return
	}
	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now().UTC()
	}

	if err := logger.LogScan(&result); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *APIServer) handleEnforceBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	var req enforcementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.TargetType == "" || req.TargetName == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_type and target_name are required"})
		return
	}

	pe := enforce.NewPolicyEngine(a.store)
	switch r.Method {
	case http.MethodPost:
		reason := req.Reason
		if reason == "" {
			reason = "blocked via REST API"
		}
		if err := pe.Block(req.TargetType, req.TargetName, reason); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if a.logger != nil {
			_ = a.logger.LogAction("api-enforce-block", req.TargetName, fmt.Sprintf("type=%s reason=%s", req.TargetType, truncate(reason, 120)))
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "blocked"})
	case http.MethodDelete:
		if err := pe.Unblock(req.TargetType, req.TargetName); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if a.logger != nil {
			_ = a.logger.LogAction("api-enforce-unblock", req.TargetName, fmt.Sprintf("type=%s", req.TargetType))
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "unblocked"})
	}
}

func (a *APIServer) handleEnforceAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	var req enforcementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.TargetType == "" || req.TargetName == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_type and target_name are required"})
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "allowed via REST API"
	}

	pe := enforce.NewPolicyEngine(a.store)
	if err := pe.Allow(req.TargetType, req.TargetName, reason); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if a.logger != nil {
		_ = a.logger.LogAction("api-enforce-allow", req.TargetName, fmt.Sprintf("type=%s reason=%s", req.TargetType, truncate(reason, 120)))
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "allowed"})
}

func (a *APIServer) handleEnforceBlocked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	entries, err := enforce.NewPolicyEngine(a.store).ListBlocked()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, toEnforcementEntries(entries))
}

func (a *APIServer) handleEnforceAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	entries, err := enforce.NewPolicyEngine(a.store).ListAllowed()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, toEnforcementEntries(entries))
}

func (a *APIServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = parsed
	}

	alerts, err := a.store.ListAlerts(limit)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, alerts)
}

func (a *APIServer) handleAuditEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}

	var event audit.Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if event.Action == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action is required"})
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Severity == "" {
		event.Severity = "INFO"
	}
	if err := a.store.LogEvent(event); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *APIServer) handlePolicyEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req policyEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Domain != "" && req.Domain != "admission" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported policy domain"})
		return
	}
	if req.Input.TargetType == "" || req.Input.TargetName == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "input.target_type and input.target_name are required"})
		return
	}

	input := policy.AdmissionInput{
		TargetType: req.Input.TargetType,
		TargetName: req.Input.TargetName,
		Path:       req.Input.Path,
		BlockList:  a.blockListEntries(),
		AllowList:  a.allowListEntries(),
	}
	if req.Input.ScanResult != nil {
		input.ScanResult = &policy.ScanResultInput{
			MaxSeverity:   req.Input.ScanResult.MaxSeverity,
			TotalFindings: req.Input.ScanResult.TotalFindings,
		}
	}

	out, err := a.evaluateAdmissionPolicy(r.Context(), input)
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": out})
}

func (a *APIServer) handleSkills(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	data, err := a.client.GetSkillsStatus(ctx)
	if err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (a *APIServer) handleMCPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusOK, []string{})
		return
	}

	seen := make(map[string]bool)
	var names []string
	for _, dir := range a.scannerCfg.MCPDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}

	a.writeJSON(w, http.StatusOK, names)
}

func (a *APIServer) handleToolsCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	data, err := a.client.GetToolsCatalog(ctx)
	if err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ---------------------------------------------------------------------------
// POST /v1/skill/scan — run skill scanner on a local path (Option 2: remote scan)
// ---------------------------------------------------------------------------

type skillScanRequest struct {
	Target string `json:"target"`
	Name   string `json:"name"`
}

func (a *APIServer) handleSkillScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Target == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}

	// Verify target exists on this host.
	// If the path doesn't exist locally, the scanner will fail with a clear
	// error — we still attempt the scan so that when the sidecar runs on the
	// same host as OpenClaw (the intended remote deployment), it works.
	if info, err := os.Stat(req.Target); err != nil || !info.IsDir() {
		// Log a warning but proceed — the scanner will produce the definitive error.
		fmt.Fprintf(os.Stderr, "[api] warning: target directory not found locally: %s\n", req.Target)
	}

	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "scanner not configured"})
		return
	}

	ss := scanner.NewSkillScanner(a.scannerCfg.Scanners.SkillScanner)

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	result, err := ss.Scan(ctx, req.Target)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogAction("api-skill-scan", req.Target, fmt.Sprintf("findings=%d max=%s", len(result.Findings), result.MaxSeverity()))
		_ = a.logger.LogScanWithVerdict(result, "")
	}

	a.writeJSON(w, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// POST /v1/skill/fetch — tar.gz a skill directory and stream it back
// ---------------------------------------------------------------------------

type skillFetchRequest struct {
	Target string `json:"target"`
}

func (a *APIServer) handleSkillFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillFetchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Target == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}

	info, err := os.Stat(req.Target)
	if err != nil || !info.IsDir() {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("target directory not found: %s", req.Target),
		})
		return
	}

	if a.logger != nil {
		_ = a.logger.LogAction("api-skill-fetch", req.Target, "streaming skill tar.gz")
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(req.Target)+".tar.gz"))
	w.WriteHeader(http.StatusOK)

	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	base := req.Target
	_ = filepath.Walk(base, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable files
		}

		// Skip node_modules and .git
		name := fi.Name()
		if fi.IsDir() && (name == "node_modules" || name == ".git") {
			return filepath.SkipDir
		}

		rel, _ := filepath.Rel(base, path)
		if rel == "." {
			return nil
		}

		// Sanitise: prevent path traversal in archive
		if strings.Contains(rel, "..") {
			return nil
		}

		header, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return nil
		}
		header.Name = rel

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if fi.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			_, _ = io.Copy(tw, f)
		}

		return nil
	})
}

// ---------------------------------------------------------------------------
// POST /v1/guardrail/event — receive verdict telemetry from the Python guardrail
// ---------------------------------------------------------------------------

type guardrailEventRequest struct {
	Direction string   `json:"direction"`
	Model     string   `json:"model"`
	Action    string   `json:"action"`
	Severity  string   `json:"severity"`
	Reason    string   `json:"reason"`
	Findings  []string `json:"findings"`
	ElapsedMs float64  `json:"elapsed_ms"`
	TokensIn  *int64   `json:"tokens_in,omitempty"`
	TokensOut *int64   `json:"tokens_out,omitempty"`
}

func (a *APIServer) handleGuardrailEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req guardrailEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Direction == "" || req.Action == "" || req.Severity == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "direction, action, and severity are required"})
		return
	}

	details := fmt.Sprintf("direction=%s action=%s severity=%s findings=%d elapsed_ms=%.1f",
		req.Direction, req.Action, req.Severity, len(req.Findings), req.ElapsedMs)
	if req.Reason != "" {
		details += fmt.Sprintf(" reason=%s", truncate(req.Reason, 120))
	}
	if a.logger != nil {
		_ = a.logger.LogAction("guardrail-verdict", req.Model, details)
	}
	if a.store != nil {
		evt := audit.Event{
			Action:    "guardrail-inspection",
			Target:    req.Model,
			Severity:  req.Severity,
			Details:   details,
			Timestamp: time.Now().UTC(),
		}
		_ = a.store.LogEvent(evt)
	}

	if a.otel != nil {
		ctx := r.Context()
		a.otel.RecordGuardrailEvaluation(ctx, "litellm-guardrail", req.Action)
		a.otel.RecordGuardrailLatency(ctx, "litellm-guardrail", req.ElapsedMs)
		if req.TokensIn != nil || req.TokensOut != nil {
			var tIn, tOut int64
			if req.TokensIn != nil {
				tIn = *req.TokensIn
			}
			if req.TokensOut != nil {
				tOut = *req.TokensOut
			}
			a.otel.RecordLLMTokens(ctx, "litellm", tIn, tOut)
		}
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type guardrailEvaluateRequest struct {
	Direction     string                      `json:"direction"`
	Model         string                      `json:"model"`
	Mode          string                      `json:"mode"`
	ScannerMode   string                      `json:"scanner_mode"`
	LocalResult   *policy.GuardrailScanResult `json:"local_result"`
	CiscoResult   *policy.GuardrailScanResult `json:"cisco_result"`
	ContentLength int                         `json:"content_length"`
	ElapsedMs     float64                     `json:"elapsed_ms"`
}

func (a *APIServer) handleGuardrailEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req guardrailEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Direction == "" || req.Mode == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "direction and mode are required"})
		return
	}

	input := policy.GuardrailInput{
		Direction:     req.Direction,
		Model:         req.Model,
		Mode:          req.Mode,
		ScannerMode:   req.ScannerMode,
		LocalResult:   req.LocalResult,
		CiscoResult:   req.CiscoResult,
		ContentLength: req.ContentLength,
	}

	out, err := a.evaluateGuardrailPolicy(r.Context(), input)
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	details := fmt.Sprintf("direction=%s action=%s severity=%s scanner_mode=%s sources=%v elapsed_ms=%.1f",
		req.Direction, out.Action, out.Severity, req.ScannerMode, out.ScannerSources, req.ElapsedMs)
	if out.Reason != "" {
		details += fmt.Sprintf(" reason=%s", truncate(out.Reason, 120))
	}
	if a.logger != nil {
		_ = a.logger.LogAction("guardrail-opa-verdict", req.Model, details)
	}
	if a.store != nil {
		evt := audit.Event{
			Action:    "guardrail-opa-inspection",
			Target:    req.Model,
			Severity:  out.Severity,
			Details:   details,
			Timestamp: time.Now().UTC(),
		}
		_ = a.store.LogEvent(evt)
	}

	if a.otel != nil {
		ctx := r.Context()
		for _, src := range out.ScannerSources {
			a.otel.RecordGuardrailEvaluation(ctx, src, out.Action)
		}
		a.otel.RecordGuardrailLatency(ctx, "opa-guardrail", req.ElapsedMs)
	}

	a.writeJSON(w, http.StatusOK, out)
}

func (a *APIServer) handleGuardrailConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := map[string]interface{}{
			"mode":         "observe",
			"scanner_mode": "local",
		}
		if a.scannerCfg != nil {
			cfg["mode"] = a.scannerCfg.Guardrail.Mode
			cfg["scanner_mode"] = a.scannerCfg.Guardrail.ScannerMode
		}
		a.writeJSON(w, http.StatusOK, cfg)

	case http.MethodPatch:
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}

		if a.scannerCfg == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not available"})
			return
		}

		changed := []string{}
		if mode, ok := req["mode"]; ok && (mode == "observe" || mode == "action") {
			a.scannerCfg.Guardrail.Mode = mode
			changed = append(changed, "mode="+mode)
		}
		if sm, ok := req["scanner_mode"]; ok && (sm == "local" || sm == "remote" || sm == "both") {
			a.scannerCfg.Guardrail.ScannerMode = sm
			changed = append(changed, "scanner_mode="+sm)
		}

		if len(changed) == 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid fields to update"})
			return
		}

		if err := a.writeGuardrailRuntime(); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		if a.logger != nil {
			_ = a.logger.LogAction("guardrail-config-reload", "", strings.Join(changed, " "))
		}

		a.writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":       "updated",
			"changed":      changed,
			"mode":         a.scannerCfg.Guardrail.Mode,
			"scanner_mode": a.scannerCfg.Guardrail.ScannerMode,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) writeGuardrailRuntime() error {
	if a.scannerCfg == nil {
		return fmt.Errorf("api: no config available")
	}
	runtimeFile := filepath.Join(a.scannerCfg.DataDir, "guardrail_runtime.json")
	data, err := json.Marshal(map[string]string{
		"mode":         a.scannerCfg.Guardrail.Mode,
		"scanner_mode": a.scannerCfg.Guardrail.ScannerMode,
	})
	if err != nil {
		return fmt.Errorf("api: marshal runtime config: %w", err)
	}
	return os.WriteFile(runtimeFile, data, 0o600)
}

func (a *APIServer) evaluateGuardrailPolicy(ctx context.Context, input policy.GuardrailInput) (*policy.GuardrailOutput, error) {
	if a.scannerCfg != nil && a.scannerCfg.PolicyDir != "" {
		engine, err := policy.New(a.scannerCfg.PolicyDir)
		if err == nil {
			out, evalErr := engine.EvaluateGuardrail(ctx, input)
			if evalErr == nil {
				return out, nil
			}
		}
	}

	sev := "NONE"
	action := "allow"
	var sources []string
	for _, res := range []*policy.GuardrailScanResult{input.LocalResult, input.CiscoResult} {
		if res == nil {
			continue
		}
		rank := map[string]int{"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
		if rank[res.Severity] > rank[sev] {
			sev = res.Severity
			action = res.Action
		}
		if res.Severity != "NONE" {
			sources = append(sources, "scanner")
		}
	}

	return &policy.GuardrailOutput{
		Action:         action,
		Severity:       sev,
		Reason:         "built-in fallback (OPA unavailable)",
		ScannerSources: sources,
	}, nil
}

// csrfProtect wraps a handler with localhost CSRF defenses. Mutating methods
// (POST, PUT, PATCH, DELETE) require:
//  1. X-DefenseClaw-Client header (blocks simple/no-cors browser requests)
//  2. Content-Type containing "application/json"
//  3. Origin, if present, must be a localhost address
//
// Read-only requests (GET, HEAD, OPTIONS) are exempt.
func csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		if r.Header.Get("X-DefenseClaw-Client") == "" {
			http.Error(w, `{"error":"missing X-DefenseClaw-Client header"}`, http.StatusForbidden)
			return
		}

		ct := r.Header.Get("Content-Type")
		if !strings.Contains(ct, "application/json") {
			http.Error(w, `{"error":"Content-Type must be application/json"}`, http.StatusUnsupportedMediaType)
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			if !isLocalhostOrigin(origin) {
				http.Error(w, `{"error":"non-localhost Origin rejected"}`, http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func isLocalhostOrigin(origin string) bool {
	for _, prefix := range []string{
		"http://127.0.0.1", "http://localhost",
		"http://[::1]", "https://127.0.0.1",
		"https://localhost", "https://[::1]",
	} {
		if strings.HasPrefix(origin, prefix) {
			return true
		}
	}
	return false
}

func (a *APIServer) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func toEnforcementEntries(entries []audit.ActionEntry) []enforcementEntry {
	out := make([]enforcementEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, enforcementEntry{
			ID:         entry.ID,
			TargetType: entry.TargetType,
			TargetName: entry.TargetName,
			Reason:     entry.Reason,
			UpdatedAt:  entry.UpdatedAt,
		})
	}
	return out
}

func (a *APIServer) blockListEntries() []policy.ListEntry {
	return a.policyListEntries(true)
}

func (a *APIServer) allowListEntries() []policy.ListEntry {
	return a.policyListEntries(false)
}

func (a *APIServer) policyListEntries(blocked bool) []policy.ListEntry {
	if a.store == nil {
		return nil
	}

	pe := enforce.NewPolicyEngine(a.store)
	var (
		actions []audit.ActionEntry
		err     error
	)
	if blocked {
		actions, err = pe.ListBlocked()
	} else {
		actions, err = pe.ListAllowed()
	}
	if err != nil {
		return nil
	}

	entries := make([]policy.ListEntry, 0, len(actions))
	for _, action := range actions {
		entries = append(entries, policy.ListEntry{
			TargetType: action.TargetType,
			TargetName: action.TargetName,
			Reason:     action.Reason,
		})
	}
	return entries
}

func (a *APIServer) evaluateAdmissionPolicy(ctx context.Context, input policy.AdmissionInput) (*policy.AdmissionOutput, error) {
	if a.scannerCfg != nil && a.scannerCfg.PolicyDir != "" {
		engine, err := policy.New(a.scannerCfg.PolicyDir)
		if err == nil {
			out, evalErr := engine.Evaluate(ctx, input)
			if evalErr == nil {
				return out, nil
			}
		}
	}

	if blocked, reason := findPolicyListEntry(input.BlockList, input.TargetType, input.TargetName); blocked {
		return &policy.AdmissionOutput{Verdict: "blocked", Reason: reason}, nil
	}
	if allowed, reason := findPolicyListEntry(input.AllowList, input.TargetType, input.TargetName); allowed {
		return &policy.AdmissionOutput{Verdict: "allowed", Reason: reason}, nil
	}
	if input.ScanResult == nil {
		return &policy.AdmissionOutput{Verdict: "scan", Reason: "scan required"}, nil
	}
	if input.ScanResult.TotalFindings <= 0 {
		return &policy.AdmissionOutput{Verdict: "clean", Reason: "scan clean"}, nil
	}
	if input.ScanResult.MaxSeverity == "HIGH" || input.ScanResult.MaxSeverity == "CRITICAL" {
		return &policy.AdmissionOutput{
			Verdict: "rejected",
			Reason:  fmt.Sprintf("max severity %s triggers block", input.ScanResult.MaxSeverity),
		}, nil
	}
	return &policy.AdmissionOutput{
		Verdict: "warning",
		Reason:  "findings present — allowed with warning",
	}, nil
}

func findPolicyListEntry(entries []policy.ListEntry, targetType, targetName string) (bool, string) {
	for _, entry := range entries {
		if entry.TargetType == targetType && entry.TargetName == targetName {
			if entry.Reason != "" {
				return true, entry.Reason
			}
			return true, fmt.Sprintf("%s %q matched policy list", targetType, targetName)
		}
	}
	return false, ""
}
