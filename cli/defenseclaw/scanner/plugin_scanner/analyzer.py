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

"""Analyzer interface and ScanContext."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from defenseclaw.scanner.plugin_scanner.types import (
    Finding,
    PluginManifest,
)


@dataclass
class SourceFile:
    """Pre-collected and parsed source file."""

    path: str
    rel_path: str
    content: str
    lines: list[str]
    code_lines: list[str]
    in_test_path: bool


@dataclass
class ScanContext:
    """Shared state passed to all analyzers."""

    plugin_dir: str
    manifest: PluginManifest | None
    source_files: list[SourceFile] = field(default_factory=list)
    profile: str = "default"
    capabilities: set[str] = field(default_factory=set)
    finding_counter: list[int] = field(default_factory=lambda: [1])  # mutable int
    previous_findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


class Analyzer(Protocol):
    """Every analyzer implements analyze(ctx) and returns findings."""

    @property
    def name(self) -> str: ...

    def analyze(self, ctx: ScanContext) -> list[Finding]: ...
