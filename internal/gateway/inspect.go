package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ToolInspectRequest is the payload for POST /api/v1/inspect/tool.
// A single endpoint handles both general tool policy checks and message
// content inspection — the handler branches on the Tool field.
type ToolInspectRequest struct {
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args,omitempty"`
	Content   string          `json:"content,omitempty"`
	Direction string          `json:"direction,omitempty"`
}

// ToolInspectVerdict is the response from the inspect endpoint.
type ToolInspectVerdict struct {
	Action   string   `json:"action"`
	Severity string   `json:"severity"`
	Reason   string   `json:"reason"`
	Findings []string `json:"findings"`
	Mode     string   `json:"mode"`
}

var secretPatterns = []string{
	"sk-", "sk-ant-", "sk-proj-", "api_key=", "apikey=",
	"-----begin rsa", "-----begin private", "-----begin openssh",
	"aws_access_key", "aws_secret_access", "password=",
	"token:", "bearer ", "ghp_", "gho_", "github_pat_",
}

var exfilPatterns = []string{
	"/etc/passwd", "/etc/shadow", "base64 -d", "base64 --decode",
	"exfiltrate", "send to my server", "curl http",
}

func scanPatterns(text string, patterns []string) []string {
	lower := strings.ToLower(text)
	var matched []string
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			matched = append(matched, p)
		}
	}
	return matched
}

// inspectToolPolicy checks whether the tool+args combination matches
// dangerous patterns or is on the block list (tool-level policy).
func (a *APIServer) inspectToolPolicy(req *ToolInspectRequest) *ToolInspectVerdict {
	var findings []string

	argsStr := strings.ToLower(string(req.Args))
	tool := strings.ToLower(req.Tool)

	isExecTool := tool == "shell" || tool == "system.run" || tool == "exec"
	if isExecTool {
		for _, p := range dangerousPatterns {
			if strings.Contains(argsStr, p) {
				findings = append(findings, "dangerous-cmd:"+p)
			}
		}
	}

	sensitiveTools := map[string]bool{
		"write_file": true, "edit_file": true,
		"delete_file": true, "move_file": true,
	}
	if sensitiveTools[tool] {
		sensitiveTargets := []string{"/etc/", "/usr/", "/var/", "/root/", "~/.ssh/"}
		for _, t := range sensitiveTargets {
			if strings.Contains(argsStr, strings.ToLower(t)) {
				findings = append(findings, "sensitive-path:"+t)
			}
		}
	}

	secretHits := scanPatterns(argsStr, secretPatterns)
	for _, h := range secretHits {
		findings = append(findings, "secret-in-args:"+h)
	}

	if len(findings) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	severity := "MEDIUM"
	for _, f := range findings {
		if strings.HasPrefix(f, "dangerous-cmd:") || strings.HasPrefix(f, "sensitive-path:") {
			severity = "HIGH"
			break
		}
	}

	action := "alert"
	if severity == "HIGH" || severity == "CRITICAL" {
		action = "block"
	}

	return &ToolInspectVerdict{
		Action:   action,
		Severity: severity,
		Reason:   fmt.Sprintf("matched: %s", strings.Join(findings[:min(len(findings), 5)], ", ")),
		Findings: findings,
	}
}

// inspectMessageContent scans outbound message content for secrets, PII,
// and data exfiltration patterns.
func (a *APIServer) inspectMessageContent(req *ToolInspectRequest) *ToolInspectVerdict {
	content := req.Content
	if content == "" {
		var parsed map[string]interface{}
		if err := json.Unmarshal(req.Args, &parsed); err == nil {
			if c, ok := parsed["content"].(string); ok {
				content = c
			} else if c, ok := parsed["body"].(string); ok {
				content = c
			}
		}
	}

	if content == "" {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	var findings []string

	secretHits := scanPatterns(content, secretPatterns)
	for _, h := range secretHits {
		findings = append(findings, "secret:"+h)
	}

	exfilHits := scanPatterns(content, exfilPatterns)
	for _, h := range exfilHits {
		findings = append(findings, "exfil:"+h)
	}

	if len(findings) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	// Outbound messages carrying secrets or exfil patterns are HIGH —
	// the content is about to leave the system boundary.
	severity := "HIGH"

	action := "block"

	return &ToolInspectVerdict{
		Action:   action,
		Severity: severity,
		Reason:   fmt.Sprintf("matched: %s", strings.Join(findings[:min(len(findings), 5)], ", ")),
		Findings: findings,
	}
}

func (a *APIServer) handleInspectTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ToolInspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Tool == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tool is required"})
		return
	}

	t0 := time.Now()

	var verdict *ToolInspectVerdict

	if strings.ToLower(req.Tool) == "message" && (req.Content != "" || req.Direction == "outbound") {
		verdict = a.inspectMessageContent(&req)
	} else {
		verdict = a.inspectToolPolicy(&req)
	}

	mode := "observe"
	if a.scannerCfg != nil {
		mode = a.scannerCfg.Guardrail.Mode
	}
	if mode == "" {
		mode = "observe"
	}
	verdict.Mode = mode

	elapsed := time.Since(t0)

	var auditAction string
	switch verdict.Action {
	case "block":
		auditAction = "inspect-tool-block"
	case "alert":
		auditAction = "inspect-tool-alert"
	default:
		auditAction = "inspect-tool-allow"
	}
	_ = a.logger.LogAction(auditAction, req.Tool,
		fmt.Sprintf("severity=%s reason=%s elapsed=%s mode=%s",
			verdict.Severity, verdict.Reason, elapsed, mode))

	a.writeJSON(w, http.StatusOK, verdict)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
