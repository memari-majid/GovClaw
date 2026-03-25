package defenseclaw.guardrail

import rego.v1

# LLM guardrail verdict policy.
# Input fields:
#   direction       - "prompt" or "completion"
#   model           - model name
#   mode            - "observe" or "action"
#   scanner_mode    - "local", "remote", or "both"
#   local_result    - {action, severity, findings[]} or null
#   cisco_result    - {action, severity, findings[], is_safe} or null
#   content_length  - int
#
# Static data (data.guardrail in data.json):
#   severity_rank.<SEV>           - int ranking (CRITICAL=4, HIGH=3, ...)
#   block_threshold               - minimum severity rank to block (default 3 = HIGH)
#   alert_threshold               - minimum severity rank to alert (default 2 = MEDIUM)
#   cisco_trust_level             - "full" | "advisory" | "none"

default severity := "NONE"
default reason := ""

# --- Determine effective severity from all scanner sources ---

effective_severity := _highest_severity

_local_sev_rank := data.guardrail.severity_rank[input.local_result.severity] if {
	input.local_result
	input.local_result.severity
} else := 0

_cisco_sev_rank := data.guardrail.severity_rank[input.cisco_result.severity] if {
	input.cisco_result
	input.cisco_result.severity
	data.guardrail.cisco_trust_level != "none"
} else := 0

_highest_sev_rank := max({_local_sev_rank, _cisco_sev_rank, 0})

_highest_severity := "CRITICAL" if _highest_sev_rank == 4

else := "HIGH" if _highest_sev_rank == 3

else := "MEDIUM" if _highest_sev_rank == 2

else := "LOW" if _highest_sev_rank == 1

else := "NONE"

severity := effective_severity

# --- Determine action ---
# Priority: observe override > advisory downgrade > block > alert > allow
# Using else-chain to avoid conflict errors.

action := "allow" if {
	input.mode == "observe"
	_highest_sev_rank >= data.guardrail.block_threshold
} else := "alert" if {
	data.guardrail.cisco_trust_level == "advisory"
	_cisco_sev_rank >= data.guardrail.block_threshold
	_local_sev_rank < data.guardrail.alert_threshold
} else := "block" if {
	_highest_sev_rank >= data.guardrail.block_threshold
} else := "alert" if {
	_highest_sev_rank >= data.guardrail.alert_threshold
} else := "allow"

# --- Build reason ---

reason := _build_reason

_local_reason := input.local_result.reason if {
	input.local_result
	input.local_result.reason != ""
} else := ""

_cisco_reason := input.cisco_result.reason if {
	input.cisco_result
	input.cisco_result.reason != ""
} else := ""

_build_reason := sprintf("%s; %s", [_local_reason, _cisco_reason]) if {
	_local_reason != ""
	_cisco_reason != ""
} else := _local_reason if {
	_local_reason != ""
} else := _cisco_reason if {
	_cisco_reason != ""
} else := ""

# --- Scanner sources ---

scanner_sources contains "local-pattern" if {
	input.local_result
	input.local_result.severity != "NONE"
}

scanner_sources contains "ai-defense" if {
	input.cisco_result
	input.cisco_result.severity != "NONE"
}

scanner_sources contains "opa-policy" if {
	_highest_sev_rank > 0
}
