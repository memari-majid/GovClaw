#!/usr/bin/env bash
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

set -euo pipefail

echo "Installing DefenseClaw scanner dependencies..."
echo ""

# Check for uv (recommended) or fall back to pip
if command -v uv &> /dev/null; then
    INSTALLER="uv pip install"
    echo "Using uv as package manager."
else
    INSTALLER="pip install"
    echo "Using pip as package manager. Consider installing uv: https://docs.astral.sh/uv/"
    pip install --upgrade pip
fi

echo ""
echo "Installing skill-scanner (cisco-ai-skill-scanner)..."
$INSTALLER cisco-ai-skill-scanner

echo ""
echo "Installing mcp-scanner (cisco-ai-mcp-scanner)..."
$INSTALLER cisco-ai-mcp-scanner

echo ""
echo "Installing aibom (cisco-aibom)..."
$INSTALLER cisco-aibom

echo ""
echo "Scanner dependencies installed."
echo ""
echo "Verify installation:"
echo "  skill-scanner --help"
echo "  mcp-scanner --help"
echo "  cisco-aibom --help"
echo ""
echo "Note: AI BOM requires a DuckDB catalog. See README.md for setup instructions."
echo "Note: Project CodeGuard rules are installed separately. See README.md."
