package audit

import "testing"

func TestInferTargetType(t *testing.T) {
	tests := []struct {
		scanner string
		want    string
	}{
		{"skill-scanner", "skill"},
		{"skill_scanner", "skill"},
		{"mcp-scanner", "mcp"},
		{"mcp_scanner", "mcp"},
		{"codeguard", "code"},
		{"aibom", "code"},
		{"clawshield-vuln", "code"},
		{"clawshield-secrets", "code"},
		{"clawshield-pii", "code"},
		{"clawshield-malware", "code"},
		{"clawshield-injection", "code"},
		{"future-scanner", "unknown"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			if got := inferTargetType(tt.scanner); got != tt.want {
				t.Errorf("inferTargetType(%q) = %q, want %q", tt.scanner, got, tt.want)
			}
		})
	}
}

func TestInferAssetTypeFromAction(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		details string
		want    string
	}{
		{"mcp action", "mcp-block", "", "mcp"},
		{"mcp in details", "block", "type=mcp reason=test", "mcp"},
		{"skill action", "skill-install", "", "skill"},
		{"skill in details", "install-clean", "type=skill scanner=x", "skill"},
		{"default to skill", "block", "reason=test", "skill"},
		{"watcher-block skill", "watcher-block", "type=skill reason=x", "skill"},
		{"watcher-block mcp", "watcher-block", "type=mcp reason=x", "mcp"},
		{"empty action", "", "", "skill"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inferAssetTypeFromAction(tt.action, tt.details); got != tt.want {
				t.Errorf("inferAssetTypeFromAction(%q, %q) = %q, want %q",
					tt.action, tt.details, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"hello world", "world", true},
		{"hello", "hello", true},
		{"hello", "xyz", false},
		{"", "", true},
		{"hello", "", true},
		{"", "x", false},
		{"type=skill scanner=x", "type=skill", true},
		{"type=mcp", "type=skill", false},
	}
	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			if got := contains(tt.s, tt.substr); got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}
