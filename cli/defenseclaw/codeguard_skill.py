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

"""Install and register the CodeGuard OpenClaw skill.

The skill ships inside the DefenseClaw repository at ``skills/codeguard/``.
This module copies it into the OpenClaw workspace skills directory so the
agent loads it automatically.

Two entry points:

* ``install_codeguard_skill(cfg)`` — copies the skill files into the
  highest-priority OpenClaw skills directory (workspace when configured,
  otherwise ``{claw_home}/skills/codeguard/``) and enables it in
  ``openclaw.json``.  Called from ``defenseclaw init`` and
  ``defenseclaw codeguard install-skill``.

* ``ensure_codeguard_skill(claw_home, openclaw_config)`` — lightweight check
  used on CLI startup to install the skill when OpenClaw appears after init.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path


def install_codeguard_skill(cfg) -> str:
    """Copy the CodeGuard skill into the OpenClaw workspace skills directory.

    Uses ``cfg.skill_dirs()`` to resolve the highest-priority directory
    (workspace skills dir when configured, otherwise the global skills dir).

    Returns a short status string for CLI output.
    """
    skill_dirs = cfg.skill_dirs()
    if not skill_dirs:
        return "skipped (no skill directories configured)"

    target_parent = skill_dirs[0]
    target_dir = os.path.join(target_parent, "codeguard")
    source_dir = _find_skill_source()

    if source_dir is None:
        return "skipped (skill source not found in package)"

    os.makedirs(target_parent, exist_ok=True)

    if os.path.isdir(target_dir):
        shutil.rmtree(target_dir)
    shutil.copytree(source_dir, target_dir)

    oc_config = _expand(cfg.claw.config_file)
    _enable_codeguard_in_openclaw(oc_config)

    return f"installed to {target_dir}"


def ensure_codeguard_skill(claw_home: str, openclaw_config: str) -> None:
    """Lightweight check: install the skill if OpenClaw exists but the skill doesn't.

    Designed to be called on CLI startup so that when a user installs OpenClaw
    after running ``defenseclaw init``, the skill appears automatically on the
    next ``defenseclaw`` invocation.
    """
    claw_home = _expand(claw_home)
    oc_config = _expand(openclaw_config)

    target_parent = _resolve_workspace_skills_dir(oc_config)
    if target_parent is None:
        target_parent = os.path.join(claw_home, "skills")

    target_dir = os.path.join(target_parent, "codeguard")

    if os.path.isdir(target_dir):
        return

    oc_binary = shutil.which("openclaw")
    if not os.path.isfile(oc_config) and not oc_binary:
        return

    source_dir = _find_skill_source()
    if source_dir is None:
        return

    os.makedirs(target_parent, exist_ok=True)
    shutil.copytree(source_dir, target_dir)
    _enable_codeguard_in_openclaw(oc_config)


def _resolve_workspace_skills_dir(openclaw_config: str) -> str | None:
    """Read the workspace from openclaw.json and return its skills subdir."""
    data = _read_openclaw_json(openclaw_config)
    if data is None:
        return None
    ws = data.get("agents", {}).get("defaults", {}).get("workspace", "")
    if ws:
        return os.path.join(_expand(ws), "skills")
    return None


def _read_openclaw_json(openclaw_config: str) -> dict | None:
    path = _expand(openclaw_config)
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _enable_codeguard_in_openclaw(openclaw_config: str) -> None:
    """Ensure ``skills.entries.codeguard`` is enabled in openclaw.json."""
    path = _expand(openclaw_config)
    if not os.path.isfile(path):
        return

    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    skills = cfg.setdefault("skills", {})
    entries = skills.setdefault("entries", {})
    cg_entry = entries.get("codeguard")
    if isinstance(cg_entry, dict) and cg_entry.get("enabled") is True:
        return

    entries["codeguard"] = {"enabled": True}

    try:
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
    except OSError:
        pass


def _find_skill_source() -> str | None:
    """Locate the ``skills/codeguard/`` directory in bundled package data or repo tree."""
    this_file = os.path.abspath(__file__)
    cli_pkg = os.path.dirname(this_file)

    bundled = os.path.join(cli_pkg, "_data", "skills", "codeguard")
    if os.path.isdir(bundled) and os.path.isfile(os.path.join(bundled, "SKILL.md")):
        return bundled

    repo_root = os.path.dirname(os.path.dirname(cli_pkg))
    candidates = [
        os.path.join(repo_root, "skills", "codeguard"),
        os.path.join(os.path.dirname(cli_pkg), "skills", "codeguard"),
    ]

    for c in candidates:
        resolved = os.path.realpath(c)
        if os.path.isdir(resolved) and os.path.isfile(os.path.join(resolved, "SKILL.md")):
            return resolved
    return None


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return str(Path.home() / p[2:])
    return p
