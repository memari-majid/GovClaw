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
 * DefenseClaw Plugin Scanner — orchestrator.
 *
 * This is the public entry point. It loads the manifest, builds the analyzer
 * pipeline via the factory, runs each analyzer, deduplicates findings, and
 * computes the assessment.
 *
 * Architecture modeled after the cisco-ai-skill-scanner:
 * - Analyzer interface (analyzer.ts)
 * - Analyzer classes (analyzer_classes.ts)
 * - Factory function (analyzer_factory.ts)
 * - Orchestrator (this file)
 *
 * Rule definitions:    ./rules.ts
 * Analysis phases:     ./analyzers.ts (legacy functions, wrapped by classes)
 * Helpers & utilities: ./helpers.ts
 */
import { readFile } from "node:fs/promises";
import { join, basename, resolve } from "node:path";
import type {
  Finding,
  ScanResult,
  ScanMetadata,
  PluginManifest,
  ScanProfile,
  PluginScanOptions,
} from "../../types.js";
import type { ScanContext } from "./analyzer.js";
import {
  makeFinding,
  deduplicateFindings,
  buildResult,
} from "./helpers.js";
import { hasInstallScripts } from "./analyzers.js";
import { buildAnalyzers } from "./analyzer_factory.js";
import {
  defaultPolicy,
  fromPreset,
  fromYaml,
  disabledAnalyzerNames,
  applySeverityOverride,
  isSuppressed,
  type PluginScanPolicy,
} from "./policy.js";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function scanPlugin(
  pluginDir: string,
  options?: PluginScanOptions,
): Promise<ScanResult> {
  const start = Date.now();
  const target = resolve(pluginDir);

  // --- Load policy ---
  let policy: PluginScanPolicy;
  if (options?.policy) {
    if (["default", "strict", "permissive"].includes(options.policy)) {
      policy = fromPreset(options.policy);
    } else {
      policy = await fromYaml(options.policy);
    }
  } else {
    policy = defaultPolicy();
  }

  // Profile from options overrides policy profile
  const profile: ScanProfile = options?.profile ?? policy.profile;

  // --- Load manifest ---
  const manifest = await loadManifest(target);
  if (!manifest) {
    const findings = [makeFinding(1, {
      rule_id: "MANIFEST-MISSING",
      severity: "MEDIUM",
      confidence: 1.0,
      title: "No plugin manifest found",
      description:
        "Plugin directory lacks a package.json, manifest.json, or plugin.json. " +
        "Cannot verify plugin identity, version, or declared permissions.",
      location: target,
      remediation: "Add a package.json with name, version, and permissions fields.",
      tags: ["supply-chain"],
    })];
    return buildResult(target, findings, start);
  }

  // --- Build analyzer pipeline (respecting policy toggles + LLM config) ---
  const analyzers = buildAnalyzers({
    profile,
    disabledAnalyzers: disabledAnalyzerNames(policy),
    llm: policy.llm,
  });

  // --- Build scan context ---
  const ctx: ScanContext = {
    pluginDir: target,
    manifest,
    sourceFiles: [], // populated by SourceAnalyzer
    profile,
    capabilities: new Set<string>(),
    findingCounter: { value: 1 },
    previousFindings: [],
    metadata: {},
  };

  // --- Run analyzers sequentially ---
  // Each analyzer may depend on ctx state set by previous analyzers.
  // MetaAnalyzer (last) reads ctx.previousFindings for cross-referencing.
  const allFindings: Finding[] = [];

  for (const analyzer of analyzers) {
    // Feed accumulated findings to meta analyzer
    if (analyzer.name === "meta") {
      ctx.previousFindings = [...allFindings];
    }

    const findings = await analyzer.analyze(ctx);

    // Assign stable IDs
    for (const f of findings) {
      if (f.id.startsWith("plugin-0") || !f.id.startsWith("plugin-")) {
        f.id = `plugin-${ctx.findingCounter.value++}`;
      }
    }

    allFindings.push(...findings);
  }

  // --- Apply policy: severity overrides + suppression ---
  for (const f of allFindings) {
    applySeverityOverride(f, policy.severity_overrides);
  }
  const policyFiltered = allFindings.filter((f) => !isSuppressed(f, policy));

  // --- Build metadata ---
  const metadata: ScanMetadata = {
    manifest_name: manifest.name,
    manifest_version: manifest.version,
    file_count: ctx.metadata.file_count ?? 0,
    total_size_bytes: ctx.metadata.total_size_bytes ?? 0,
    has_lockfile: ctx.metadata.has_lockfile ?? false,
    has_install_scripts: hasInstallScripts(manifest),
    detected_capabilities: [...ctx.capabilities].sort(),
  };

  return buildResult(target, deduplicateFindings(policyFiltered), start, metadata);
}

// ---------------------------------------------------------------------------
// Manifest loading
// ---------------------------------------------------------------------------

async function loadManifest(dir: string): Promise<PluginManifest | null> {
  for (const name of ["package.json", "manifest.json", "plugin.json"]) {
    try {
      const raw = await readFile(join(dir, name), "utf-8");
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      return normalizeManifest(parsed, name);
    } catch {
      continue;
    }
  }
  return null;
}

function normalizeManifest(
  raw: Record<string, unknown>,
  filename: string,
): PluginManifest {
  const manifest: PluginManifest = {
    name: String(raw["name"] ?? basename(filename)),
    version: raw["version"] as string | undefined,
    description: raw["description"] as string | undefined,
    source: filename,
  };

  if (Array.isArray(raw["permissions"])) {
    manifest.permissions = raw["permissions"] as string[];
  }

  const defenseclaw = raw["defenseclaw"] as Record<string, unknown> | undefined;
  if (defenseclaw && Array.isArray(defenseclaw["permissions"])) {
    manifest.permissions = defenseclaw["permissions"] as string[];
  }

  if (Array.isArray(raw["tools"])) {
    manifest.tools = raw["tools"] as import("../../types.js").ToolManifest[];
  }

  if (Array.isArray(raw["commands"])) {
    manifest.commands = raw["commands"] as Array<{
      name: string;
      description?: string;
      args?: Array<{ name: string; required?: boolean }>;
    }>;
  }

  if (raw["dependencies"] && typeof raw["dependencies"] === "object") {
    manifest.dependencies = raw["dependencies"] as Record<string, string>;
  }
  if (raw["devDependencies"] && typeof raw["devDependencies"] === "object") {
    manifest.dependencies = {
      ...manifest.dependencies,
      ...(raw["devDependencies"] as Record<string, string>),
    };
  }

  if (raw["scripts"] && typeof raw["scripts"] === "object") {
    manifest.scripts = raw["scripts"] as Record<string, string>;
  }

  return manifest;
}
