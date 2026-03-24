package scanner

import (
	"testing"
)

// TestParsePluginOutput_RealFormat verifies that parsePluginOutput correctly
// handles the actual JSON output format from the TypeScript plugin scanner
// (extensions/defenseclaw/src/types.ts ScanResult).
func TestParsePluginOutput_RealFormat(t *testing.T) {
	// This is the actual output format from defenseclaw-plugin-scanner.
	// It's a full ScanResult, not just {"findings": [...]}.
	raw := []byte(`{
		"scanner": "defenseclaw-plugin-scanner",
		"target": "/tmp/test-plugin",
		"timestamp": "2026-03-24T12:00:00.000Z",
		"findings": [
			{
				"id": "plugin-1",
				"rule_id": "PERM-DANGEROUS",
				"severity": "HIGH",
				"confidence": 0.9,
				"title": "Dangerous permission: fs:*",
				"description": "Plugin requests broad filesystem access",
				"evidence": "\"permissions\": [\"fs:*\"]",
				"location": "package.json",
				"remediation": "Request specific file paths instead of fs:*",
				"scanner": "defenseclaw-plugin-scanner",
				"tags": ["permissions"],
				"taxonomy": {"objective": "OB-009", "technique": "AITech-9.1"},
				"occurrence_count": 1,
				"suppressed": false
			},
			{
				"id": "plugin-2",
				"rule_id": "SRC-EVAL",
				"severity": "CRITICAL",
				"confidence": 0.95,
				"title": "Dynamic code execution via eval()",
				"description": "eval() can execute arbitrary code",
				"evidence": "eval(userInput)",
				"location": "src/index.ts:42",
				"remediation": "Remove eval() usage",
				"scanner": "defenseclaw-plugin-scanner",
				"tags": ["code-execution"],
				"taxonomy": {"objective": "OB-005", "technique": "AITech-5.1"},
				"occurrence_count": 1,
				"suppressed": false
			},
			{
				"id": "plugin-3",
				"rule_id": "SRC-CRED",
				"severity": "MEDIUM",
				"confidence": 0.7,
				"title": "Possible credential access",
				"description": "Reads credential files",
				"location": "src/helper.ts:10",
				"scanner": "defenseclaw-plugin-scanner",
				"tags": ["credential-theft"],
				"occurrence_count": 1,
				"suppressed": true,
				"suppression_reason": "false positive"
			}
		],
		"duration_ns": 150000000,
		"metadata": {
			"manifest_name": "test-plugin",
			"manifest_version": "1.0.0",
			"file_count": 5,
			"total_size_bytes": 12345,
			"has_lockfile": true,
			"has_install_scripts": false,
			"detected_capabilities": ["eval", "fs"]
		},
		"assessment": {
			"verdict": "malicious",
			"confidence": 0.95,
			"summary": "Plugin has 1 critical finding(s).",
			"categories": []
		}
	}`)

	findings, err := parsePluginOutput(raw)
	if err != nil {
		t.Fatalf("parsePluginOutput: %v", err)
	}

	// Should have 2 findings (3rd is suppressed)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (1 suppressed), got %d", len(findings))
	}

	// Verify first finding
	if findings[0].ID != "plugin-1" {
		t.Errorf("finding[0].ID = %q, want plugin-1", findings[0].ID)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("finding[0].Severity = %q, want HIGH", findings[0].Severity)
	}
	if findings[0].Title != "Dangerous permission: fs:*" {
		t.Errorf("finding[0].Title = %q", findings[0].Title)
	}
	if findings[0].Location != "package.json" {
		t.Errorf("finding[0].Location = %q, want package.json", findings[0].Location)
	}
	if len(findings[0].Tags) != 1 || findings[0].Tags[0] != "permissions" {
		t.Errorf("finding[0].Tags = %v, want [permissions]", findings[0].Tags)
	}

	// Verify second finding (CRITICAL)
	if findings[1].Severity != SeverityCritical {
		t.Errorf("finding[1].Severity = %q, want CRITICAL", findings[1].Severity)
	}

	// Verify MaxSeverity works with parsed findings
	result := &ScanResult{Findings: findings}
	if result.MaxSeverity() != SeverityCritical {
		t.Errorf("MaxSeverity = %q, want CRITICAL", result.MaxSeverity())
	}
	if result.IsClean() {
		t.Error("expected not clean")
	}
}

func TestParsePluginOutput_EmptyFindings(t *testing.T) {
	raw := []byte(`{
		"scanner": "defenseclaw-plugin-scanner",
		"target": "/tmp/clean-plugin",
		"timestamp": "2026-03-24T12:00:00.000Z",
		"findings": [],
		"duration_ns": 50000000,
		"assessment": {
			"verdict": "benign",
			"confidence": 0.9,
			"summary": "No security issues detected.",
			"categories": []
		}
	}`)

	findings, err := parsePluginOutput(raw)
	if err != nil {
		t.Fatalf("parsePluginOutput: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}

	result := &ScanResult{Findings: findings}
	if !result.IsClean() {
		t.Error("expected clean scan")
	}
}

func TestParsePluginOutput_AllSuppressed(t *testing.T) {
	raw := []byte(`{
		"scanner": "defenseclaw-plugin-scanner",
		"target": "/tmp/suppressed-plugin",
		"timestamp": "2026-03-24T12:00:00.000Z",
		"findings": [
			{
				"id": "plugin-1",
				"severity": "HIGH",
				"title": "False positive",
				"description": "Not a real issue",
				"scanner": "defenseclaw-plugin-scanner",
				"suppressed": true,
				"suppression_reason": "known safe"
			}
		]
	}`)

	findings, err := parsePluginOutput(raw)
	if err != nil {
		t.Fatalf("parsePluginOutput: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (all suppressed), got %d", len(findings))
	}
}
