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

package defenseclaw.sandbox_test

import rego.v1

import data.defenseclaw.sandbox

test_allowed_endpoints_filter_denied if {
	result := sandbox with input as {
		"skill_name": "my-skill",
		"requested_endpoints": ["api.github.com", "169.254.169.254", "safe.example.com"],
		"requested_permissions": ["read"],
	}
		with data.sandbox as {
			"default_permissions": ["network"],
			"denied_endpoints_global": ["169.254.169.254"],
		}
		with data.firewall as {
			"blocked_destinations": ["10.0.0.1"],
		}

	"api.github.com" in result.allowed_endpoints
	"safe.example.com" in result.allowed_endpoints
	not "169.254.169.254" in result.allowed_endpoints
}

test_denied_from_request if {
	result := sandbox with input as {
		"skill_name": "my-skill",
		"requested_endpoints": ["169.254.169.254", "10.0.0.1"],
		"requested_permissions": [],
	}
		with data.sandbox as {
			"default_permissions": [],
			"denied_endpoints_global": ["169.254.169.254"],
		}
		with data.firewall as {
			"blocked_destinations": ["10.0.0.1"],
		}

	"169.254.169.254" in result.denied_from_request
	"10.0.0.1" in result.denied_from_request
}

test_permissions_merged if {
	result := sandbox with input as {
		"skill_name": "my-skill",
		"requested_endpoints": [],
		"requested_permissions": ["write", "execute"],
	}
		with data.sandbox as {
			"default_permissions": ["read", "network"],
			"denied_endpoints_global": [],
		}
		with data.firewall as {
			"blocked_destinations": [],
		}

	"read" in result.permissions
	"network" in result.permissions
	"write" in result.permissions
	"execute" in result.permissions
}

test_skill_always_allowed if {
	result := sandbox with input as {
		"skill_name": "my-special-skill",
		"requested_endpoints": [],
		"requested_permissions": [],
	}
		with data.sandbox as {
			"default_permissions": [],
			"denied_endpoints_global": [],
		}
		with data.firewall as {
			"blocked_destinations": [],
		}

	"my-special-skill" in result.allowed_skills
}