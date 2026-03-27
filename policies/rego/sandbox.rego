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

package defenseclaw.sandbox

import rego.v1

# Generates OpenShell sandbox policy for a skill.
# Input fields:
#   skill_name            - name of the skill being sandboxed
#   requested_endpoints   - endpoints the skill wants to access
#   requested_permissions - permissions the skill requests
#
# Static data (data.json):
#   sandbox.denied_endpoints_global - always-denied endpoints
#   sandbox.default_permissions     - baseline permissions granted
#   firewall.blocked_destinations   - destinations blocked by firewall

default version := "1"

# Endpoints that are always denied regardless of request.
denied_endpoints contains ep if {
	some ep in data.sandbox.denied_endpoints_global
}

denied_endpoints contains ep if {
	some ep in data.firewall.blocked_destinations
}

# Filter requested endpoints: allow those not globally denied.
allowed_endpoints contains ep if {
	some ep in input.requested_endpoints
	not ep in denied_endpoints
}

# Denied endpoints from the request that are globally blocked.
denied_from_request contains ep if {
	some ep in input.requested_endpoints
	ep in denied_endpoints
}

# Merge default permissions with requested permissions.
permissions contains perm if {
	some perm in data.sandbox.default_permissions
}

permissions contains perm if {
	some perm in input.requested_permissions
}

# The skill itself is always allowed.
allowed_skills contains input.skill_name

# Skills that are denied (placeholder for future rules).
denied_skills := set()