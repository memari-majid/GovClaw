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

"""CodeGuard self-check tool for OpenClaw agents.

Allows the agent to validate code against CodeGuard rules before writing it,
via the DefenseClaw sidecar API.  This is an optional self-verification step;
the sidecar's inspectToolPolicy enforces rules regardless.

Usage by the agent:
    result = run(code="import os\\nos.system(cmd)", filename="app.py")
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.error
import urllib.request

SIDECAR_URL = os.environ.get("DEFENSECLAW_SIDECAR_URL", "http://127.0.0.1:18790")
TIMEOUT_S = 10


def run(code: str, filename: str = "check.py") -> str:
    """Scan code content for security issues.

    Writes code to a temporary file and sends it to the DefenseClaw sidecar's
    /api/v1/scan/code endpoint.  Returns a human-readable summary.

    Args:
        code: Source code to check.
        filename: Filename hint for extension-based rule filtering.

    Returns:
        "clean" if no findings, otherwise a formatted list of issues.
    """
    ext = os.path.splitext(filename)[1] or ".py"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=ext, delete=False, prefix="codeguard-check-"
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        return _scan_via_sidecar(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _scan_via_sidecar(path: str) -> str:
    payload = json.dumps({"path": path}).encode("utf-8")
    req = urllib.request.Request(
        f"{SIDECAR_URL}/api/v1/scan/code",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-DefenseClaw-Client": "codeguard-skill",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        return f"error: could not reach sidecar at {SIDECAR_URL} ({exc})"

    findings = data.get("findings") or []
    if not findings:
        return "clean"

    lines = [f"{len(findings)} issue(s) found:\n"]
    for f in findings:
        sev = f.get("severity", "?")
        rid = f.get("id", "?")
        title = f.get("title", "")
        loc = f.get("location", "")
        remedy = f.get("remediation", "")
        lines.append(f"  [{sev}] {rid}: {title}")
        if loc:
            lines.append(f"         at {loc}")
        if remedy:
            lines.append(f"         fix: {remedy}")
        lines.append("")
    return "\n".join(lines)
