/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Analyzer interface and ScanContext — modeled after the skill scanner's
 * BaseAnalyzer / Skill pattern (skill_scanner/core/analyzers/base.py).
 *
 * Every analyzer implements `analyze(ctx)` and returns findings.
 * The factory function `buildAnalyzers()` composes the analyzer list.
 */
import type {
  Finding,
  PluginManifest,
  ScanProfile,
  ScanMetadata,
} from "../../types.js";

// ---------------------------------------------------------------------------
// Scan context — shared state passed to all analyzers
// ---------------------------------------------------------------------------

export interface SourceFile {
  /** Absolute path to the file. */
  path: string;
  /** Path relative to the plugin root. */
  relPath: string;
  /** Raw file content. */
  content: string;
  /** Lines split from content. */
  lines: string[];
  /** Lines with single-line comments stripped (for pattern matching). */
  codeLines: string[];
  /** Whether this file is in a test/fixture/dist path. */
  inTestPath: boolean;
}

export interface ScanContext {
  /** Absolute path to the plugin directory. */
  pluginDir: string;
  /** Parsed plugin manifest (null if missing). */
  manifest: PluginManifest | null;
  /** Pre-collected and parsed source files (.ts, .js, .mjs). */
  sourceFiles: SourceFile[];
  /** Active scan profile. */
  profile: ScanProfile;
  /** Detected capabilities (mutated by analyzers). */
  capabilities: Set<string>;
  /** Running finding counter for stable IDs (mutated by analyzers). */
  findingCounter: { value: number };
  /** Findings from previous analyzers (for meta/cross-reference). */
  previousFindings: Finding[];
  /** Metadata collected during scanning. */
  metadata: Partial<ScanMetadata>;
}

// ---------------------------------------------------------------------------
// Analyzer interface
// ---------------------------------------------------------------------------

export interface Analyzer {
  /** Unique analyzer name (used for attribution and toggling). */
  readonly name: string;
  /** Run analysis and return findings. */
  analyze(ctx: ScanContext): Promise<Finding[]>;
}

// ---------------------------------------------------------------------------
// Analyzer factory options
// ---------------------------------------------------------------------------

export interface BuildAnalyzersOptions {
  profile?: ScanProfile;
  /** Disabled analyzer names — these will be excluded from the pipeline. */
  disabledAnalyzers?: string[];
}
