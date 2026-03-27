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

package defenseclaw.firewall_test

import rego.v1

import data.defenseclaw.firewall

# --- Blocked destination ---

test_blocked_destination if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "169.254.169.254",
		"port": 80,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": ["169.254.169.254"],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [443, 80],
		}

	result.action == "deny"
}

# --- Allowed domain + port ---

test_allowed_domain_and_port if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "api.github.com",
		"port": 443,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": ["169.254.169.254"],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [443],
		}

	result.action == "allow"
	result.rule_name == "domain-allowlist"
}

# --- Domain allowed but port restricted ---

test_allowed_domain_wrong_port if {
	result := firewall with input as {
		"target_type": "mcp",
		"destination": "api.github.com",
		"port": 8080,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": [],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [443],
		}

	result.action == "deny"
	result.rule_name == "port-restricted"
}

# --- Unknown domain: default deny ---

test_unknown_domain_deny if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "evil.com",
		"port": 443,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": [],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [443],
		}

	result.action == "deny"
}

# --- Default allow policy ---

test_default_allow_policy if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "anywhere.com",
		"port": 443,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "allow",
			"blocked_destinations": ["169.254.169.254"],
			"allowed_domains": [],
			"allowed_ports": [],
		}

	result.action == "allow"
}

# --- Empty allowed_ports means all ports allowed ---

test_empty_ports_allows_all if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "api.github.com",
		"port": 9999,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": [],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [],
		}

	result.action == "allow"
}