package policy

// AdmissionInput is the structured input passed to the OPA admission policy.
type AdmissionInput struct {
	TargetType string          `json:"target_type"`
	TargetName string          `json:"target_name"`
	Path       string          `json:"path"`
	BlockList  []ListEntry     `json:"block_list"`
	AllowList  []ListEntry     `json:"allow_list"`
	ScanResult *ScanResultInput `json:"scan_result,omitempty"`
}

// ListEntry represents one entry in the block or allow list.
type ListEntry struct {
	TargetType string `json:"target_type"`
	TargetName string `json:"target_name"`
	Reason     string `json:"reason"`
}

// ScanResultInput is the scan result subset needed by OPA.
type ScanResultInput struct {
	MaxSeverity   string `json:"max_severity"`
	TotalFindings int    `json:"total_findings"`
}

// AdmissionOutput is the structured output from the OPA admission policy.
type AdmissionOutput struct {
	Verdict    string `json:"verdict"`
	Reason     string `json:"reason"`
	FileAction string `json:"file_action"`
}

// GuardrailScanResult is a scanner's verdict passed into the guardrail policy.
type GuardrailScanResult struct {
	Action   string   `json:"action"`
	Severity string   `json:"severity"`
	Findings []string `json:"findings"`
	Reason   string   `json:"reason"`
	IsSafe   *bool    `json:"is_safe,omitempty"`
}

// GuardrailInput is sent by the Python guardrail to evaluate via OPA.
type GuardrailInput struct {
	Direction     string               `json:"direction"`
	Model         string               `json:"model"`
	Mode          string               `json:"mode"`
	ScannerMode   string               `json:"scanner_mode"`
	LocalResult   *GuardrailScanResult `json:"local_result"`
	CiscoResult   *GuardrailScanResult `json:"cisco_result"`
	ContentLength int                  `json:"content_length"`
}

// GuardrailOutput is the OPA-determined verdict returned to the Python guardrail.
type GuardrailOutput struct {
	Action         string   `json:"action"`
	Severity       string   `json:"severity"`
	Reason         string   `json:"reason"`
	ScannerSources []string `json:"scanner_sources"`
}
