# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

package defenseclaw.audit_test

import rego.v1

import data.defenseclaw.audit

test_retain_within_period if {
	result := audit with input as {
		"event_type": "scan",
		"severity": "MEDIUM",
		"age_days": 30,
		"export_targets": ["splunk"],
	}
		with data.audit as {"retention_days": 90, "log_all_actions": true, "log_scan_results": true}
		with data.severity_ranking as {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	result.retain == true
}

test_expire_old_low_severity if {
	result := audit with input as {
		"event_type": "admission",
		"severity": "LOW",
		"age_days": 100,
		"export_targets": [],
	}
		with data.audit as {"retention_days": 90, "log_all_actions": true, "log_scan_results": true}
		with data.severity_ranking as {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	result.retain == false
}

test_retain_high_severity_indefinitely if {
	result := audit with input as {
		"event_type": "admission",
		"severity": "HIGH",
		"age_days": 999,
		"export_targets": ["splunk"],
	}
		with data.audit as {"retention_days": 90, "log_all_actions": true, "log_scan_results": true}
		with data.severity_ranking as {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	result.retain == true
}

test_export_high_severity if {
	result := audit with input as {
		"event_type": "admission",
		"severity": "CRITICAL",
		"age_days": 1,
		"export_targets": ["splunk", "syslog"],
	}
		with data.audit as {"retention_days": 90, "log_all_actions": true, "log_scan_results": true}
		with data.severity_ranking as {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	"splunk" in result.export_to
	"syslog" in result.export_to
}

test_export_scan_results_when_configured if {
	result := audit with input as {
		"event_type": "scan",
		"severity": "LOW",
		"age_days": 1,
		"export_targets": ["splunk"],
	}
		with data.audit as {"retention_days": 90, "log_all_actions": true, "log_scan_results": true}
		with data.severity_ranking as {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	"splunk" in result.export_to
}

test_no_export_low_severity_non_scan if {
	result := audit with input as {
		"event_type": "enforcement",
		"severity": "INFO",
		"age_days": 1,
		"export_targets": ["splunk"],
	}
		with data.audit as {"retention_days": 90, "log_all_actions": true, "log_scan_results": true}
		with data.severity_ranking as {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	count(result.export_to) == 0
}