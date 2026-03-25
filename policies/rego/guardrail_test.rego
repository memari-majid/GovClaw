package defenseclaw.guardrail_test

import data.defenseclaw.guardrail
import rego.v1

# --- Test data wired via data.guardrail in data.json ---

test_allow_when_no_findings if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "allow", "severity": "NONE", "findings": [], "reason": ""},
		"cisco_result": null,
		"content_length": 100,
	}

	result.action == "allow"
	result.severity == "NONE"
}

test_block_on_high_local if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "HIGH", "findings": ["ignore previous"], "reason": "matched: ignore previous"},
		"cisco_result": null,
		"content_length": 200,
	}

	result.action == "block"
	result.severity == "HIGH"
}

test_alert_on_medium_local if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["sk-"], "reason": "matched: sk-"},
		"cisco_result": null,
		"content_length": 150,
	}

	result.action == "alert"
	result.severity == "MEDIUM"
}

test_observe_mode_never_blocks if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "observe",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "HIGH", "findings": ["jailbreak"], "reason": "matched: jailbreak"},
		"cisco_result": null,
		"content_length": 200,
	}

	result.action == "allow"
	result.severity == "HIGH"
}

test_cisco_only_block if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "remote",
		"local_result": null,
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Prompt Injection"], "reason": "cisco: Prompt Injection"},
		"content_length": 300,
	}

	result.action == "block"
	result.severity == "HIGH"
}

test_both_mode_cisco_escalates if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "both",
		"local_result": {"action": "allow", "severity": "NONE", "findings": [], "reason": ""},
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["SECURITY_VIOLATION"], "reason": "cisco: SECURITY_VIOLATION"},
		"content_length": 400,
	}

	result.action == "block"
	result.severity == "HIGH"
}

test_both_mode_combined_reasons if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "both",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["sk-"], "reason": "matched: sk-"},
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Data Leak"], "reason": "cisco: Data Leak"},
		"content_length": 500,
	}

	result.severity == "HIGH"
	result.action == "block"
	contains(result.reason, "matched: sk-")
	contains(result.reason, "cisco: Data Leak")
}

test_advisory_cisco_downgrades_to_alert if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "both",
		"local_result": {"action": "allow", "severity": "NONE", "findings": [], "reason": ""},
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Prompt Injection"], "reason": "cisco: Prompt Injection"},
		"content_length": 300,
	}
		with data.guardrail.cisco_trust_level as "advisory"

	result.action == "alert"
}

test_scanner_sources_populated if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "both",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["sk-"], "reason": "matched: sk-"},
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Prompt Injection"], "reason": "cisco: Prompt Injection"},
		"content_length": 500,
	}

	"local-pattern" in result.scanner_sources
	"ai-defense" in result.scanner_sources
	"opa-policy" in result.scanner_sources
}

test_cisco_trust_none_ignores_cisco if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "both",
		"local_result": {"action": "allow", "severity": "NONE", "findings": [], "reason": ""},
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Prompt Injection"], "reason": "cisco: Prompt Injection"},
		"content_length": 300,
	}
		with data.guardrail.cisco_trust_level as "none"

	result.action == "allow"
	result.severity == "NONE"
}
