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
 * Centralized analyzer construction — modeled after the skill scanner's
 * build_analyzers() in analyzer_factory.py.
 *
 * Every entry point (CLI binary, VSCode extension, API) MUST build analyzers
 * through this function so that:
 * - All core analyzers are always included.
 * - Analyzer toggling via disabledAnalyzers is respected.
 * - LLM analyzers are included when configured.
 * - Adding or removing a core analyzer only requires a change here.
 */
import type { Analyzer, BuildAnalyzersOptions } from "./analyzer.js";
import type { LLMPolicy } from "./policy.js";
import {
  PermissionsAnalyzer,
  DependencyAnalyzer,
  InstallScriptAnalyzer,
  ToolAnalyzer,
  SourceAnalyzer,
  DirectoryStructureAnalyzer,
  ClawManifestAnalyzer,
  BundleSizeAnalyzer,
  JsonConfigAnalyzer,
  LockfileAnalyzer,
  MetaAnalyzer,
} from "./analyzer_classes.js";
import { LLMAnalyzer } from "./llm_analyzer.js";

/**
 * Build the full analyzer pipeline.
 *
 * Core analyzers are always included unless explicitly disabled.
 * LLM analyzer is included when llmPolicy.enabled is true.
 * MetaAnalyzer runs last with LLM enhancement when available.
 */
export function buildAnalyzers(options?: BuildAnalyzersOptions & { llm?: LLMPolicy }): Analyzer[] {
  const disabled = new Set(options?.disabledAnalyzers ?? []);

  // Phase 1: Pattern-based analyzers
  const core: Analyzer[] = [
    new PermissionsAnalyzer(),
    new DependencyAnalyzer(),
    new InstallScriptAnalyzer(),
    new ToolAnalyzer(),
    new SourceAnalyzer(),
    new DirectoryStructureAnalyzer(),
    new ClawManifestAnalyzer(),
    new BundleSizeAnalyzer(),
    new JsonConfigAnalyzer(),
    new LockfileAnalyzer(),
  ];

  const filtered = core.filter((a) => !disabled.has(a.name));

  // Phase 2: LLM analyzer (opt-in, runs after pattern analyzers)
  if (options?.llm?.enabled && !disabled.has("llm")) {
    filtered.push(new LLMAnalyzer({
      model: options.llm.model,
      apiKey: options.llm.api_key || undefined,
      apiBase: options.llm.api_base || undefined,
      provider: options.llm.provider || undefined,
      maxTokens: options.llm.max_output_tokens,
      consensusRuns: options.llm.consensus_runs,
      pythonBinary: options.llm.python_binary || undefined,
    }));
  }

  // Phase 3: Meta analyzer (last — cross-references all previous findings)
  // Gets LLM config for optional LLM-powered validation/correlation
  if (!disabled.has("meta")) {
    filtered.push(new MetaAnalyzer(options?.llm));
  }

  return filtered;
}
