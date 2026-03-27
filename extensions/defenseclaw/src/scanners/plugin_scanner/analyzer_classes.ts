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
 * Analyzer class implementations — each wraps an existing analysis function
 * from analyzers.ts behind the Analyzer interface.
 *
 * The analysis logic is unchanged; only the orchestration layer is new.
 * This enables composable pipelines, toggling, and future policy integration.
 */
import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { Finding, Severity, ScanProfile } from "../../types.js";
import type { Analyzer, ScanContext, SourceFile } from "./analyzer.js";
import type { LLMPolicy } from "./policy.js";
import {
  checkPermissions,
  checkDependencies,
  checkInstallScripts,
  hasInstallScripts,
  checkTool,
  scanSourceFiles,
  scanDirectoryStructure,
  scanClawManifest,
  scanBundleSize,
  scanJsonConfigs,
} from "./analyzers.js";
import {
  makeFinding,
  checkLockfilePresence,
  dirExists,
} from "./helpers.js";

// ---------------------------------------------------------------------------
// Manifest analyzers
// ---------------------------------------------------------------------------

export class PermissionsAnalyzer implements Analyzer {
  readonly name = "permissions";
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    if (!ctx.manifest) return [];
    const findings: Finding[] = [];
    checkPermissions(ctx.manifest, findings, ctx.pluginDir);
    return findings;
  }
}

export class DependencyAnalyzer implements Analyzer {
  readonly name = "dependencies";
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    if (!ctx.manifest) return [];
    const findings: Finding[] = [];
    checkDependencies(ctx.manifest, findings, ctx.pluginDir);
    return findings;
  }
}

export class InstallScriptAnalyzer implements Analyzer {
  readonly name = "install-scripts";
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    if (!ctx.manifest) return [];
    const findings: Finding[] = [];
    checkInstallScripts(ctx.manifest, findings, ctx.pluginDir);
    return findings;
  }
}

export class ToolAnalyzer implements Analyzer {
  readonly name = "tools";
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    if (!ctx.manifest?.tools) return [];
    const findings: Finding[] = [];
    for (const tool of ctx.manifest.tools) {
      checkTool(tool, findings, ctx.pluginDir);
    }
    return findings;
  }
}

// ---------------------------------------------------------------------------
// Source code analyzer
// ---------------------------------------------------------------------------

export class SourceAnalyzer implements Analyzer {
  readonly name = "source";
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { fileCount, totalBytes } = await scanSourceFiles(
      ctx.pluginDir, findings, ctx.capabilities, ctx.profile,
    );
    ctx.metadata.file_count = fileCount;
    ctx.metadata.total_size_bytes = totalBytes;
    return findings;
  }
}

// ---------------------------------------------------------------------------
// Structure analyzers
// ---------------------------------------------------------------------------

export class DirectoryStructureAnalyzer implements Analyzer {
  readonly name = "directory-structure";
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    await scanDirectoryStructure(ctx.pluginDir, findings);
    return findings;
  }
}

export class ClawManifestAnalyzer implements Analyzer {
  readonly name = "claw-manifest";
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    await scanClawManifest(ctx.pluginDir, findings);
    return findings;
  }
}

export class BundleSizeAnalyzer implements Analyzer {
  readonly name = "bundle-size";
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    await scanBundleSize(ctx.pluginDir, findings);
    return findings;
  }
}

export class JsonConfigAnalyzer implements Analyzer {
  readonly name = "json-configs";
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    await scanJsonConfigs(ctx.pluginDir, findings);
    return findings;
  }
}

export class LockfileAnalyzer implements Analyzer {
  readonly name = "lockfile";
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    const hasLockfile = await checkLockfilePresence(ctx.pluginDir);
    ctx.metadata.has_lockfile = hasLockfile;

    if (!hasLockfile && ctx.manifest?.dependencies &&
        Object.keys(ctx.manifest.dependencies).length > 0) {
      const isDistributed = !(await dirExists(join(ctx.pluginDir, "node_modules")));
      if (!isDistributed) {
        return [makeFinding(ctx.findingCounter.value++, {
          rule_id: "STRUCT-NO-LOCKFILE",
          severity: "MEDIUM",
          confidence: 1.0,
          title: "No lockfile found",
          description:
            "Plugin has dependencies but no package-lock.json, yarn.lock, or pnpm-lock.yaml. " +
            "Without a lockfile, builds are non-deterministic and vulnerable to dependency confusion.",
          location: ctx.pluginDir,
          remediation: "Run npm install to generate a package-lock.json and commit it.",
          tags: ["supply-chain"],
        })];
      }
    }

    return [];
  }
}

// ---------------------------------------------------------------------------
// Meta analyzer — cross-references findings from other analyzers
// ---------------------------------------------------------------------------

export class MetaAnalyzer implements Analyzer {
  readonly name = "meta";
  private llmPolicy?: LLMPolicy;

  constructor(llmPolicy?: LLMPolicy) {
    this.llmPolicy = llmPolicy;
  }

  async analyze(ctx: ScanContext): Promise<Finding[]> {
    const prev = ctx.previousFindings;
    if (prev.length === 0) return [];

    const findings: Finding[] = [];
    const hasRule = (id: string) => prev.some((f) => f.rule_id === id);
    const hasTag = (tag: string) => prev.some((f) => f.tags?.includes(tag));

    // Chain: eval/exec + network + credential access = exfiltration chain
    const hasCodeExec = hasRule("SRC-EVAL") || hasRule("SRC-NEW-FUNC") ||
                        hasRule("SRC-CHILD-PROC") || hasRule("SRC-EXEC");
    const hasNetwork = hasTag("exfiltration") || hasTag("network-access") ||
                       hasRule("SRC-FETCH");
    const hasCreds = hasTag("credential-theft") || hasRule("CRED-OPENCLAW-DIR") ||
                     hasRule("CRED-OPENCLAW-ENV");

    if (hasCodeExec && hasNetwork && hasCreds) {
      findings.push(makeFinding(ctx.findingCounter.value++, {
        rule_id: "META-EXFIL-CHAIN",
        severity: "CRITICAL",
        confidence: 0.95,
        title: "Likely credential exfiltration chain detected",
        description:
          "Plugin combines code execution, network access, and credential file reads. " +
          "This multi-signal pattern is a strong indicator of data theft.",
        remediation: "Investigate the plugin immediately. This pattern is rarely legitimate.",
        tags: ["exfiltration", "credential-theft"],
      }));
    }

    // Chain: obfuscation + gateway manipulation = evasive attack
    if (hasTag("obfuscation") && hasTag("gateway-manipulation")) {
      findings.push(makeFinding(ctx.findingCounter.value++, {
        rule_id: "META-EVASIVE-ATTACK",
        severity: "CRITICAL",
        confidence: 0.9,
        title: "Obfuscated gateway manipulation detected",
        description:
          "Plugin uses code obfuscation combined with gateway manipulation patterns. " +
          "This suggests intentional evasion of security scanning.",
        remediation: "Block this plugin immediately and investigate its source.",
        tags: ["obfuscation", "gateway-manipulation"],
      }));
    }

    // Chain: install scripts + risky deps + no lockfile = supply chain surface
    if (hasRule("SCRIPT-INSTALL-HOOK") && hasRule("DEP-RISKY") && hasRule("STRUCT-NO-LOCKFILE")) {
      findings.push(makeFinding(ctx.findingCounter.value++, {
        rule_id: "META-SUPPLY-CHAIN",
        severity: "HIGH",
        confidence: 0.85,
        title: "Supply chain attack surface: install hooks + risky deps + no lockfile",
        description:
          "Plugin has install scripts that run automatically, depends on packages that can execute " +
          "arbitrary code, and lacks a lockfile to pin dependency versions. This combination " +
          "creates a broad supply chain attack surface.",
        remediation:
          "Remove install scripts, pin dependencies to specific versions, and add a lockfile.",
        tags: ["supply-chain"],
      }));
    }

    // Chain: cognitive tampering + obfuscation = persistent agent compromise
    if (hasTag("cognitive-tampering") && hasTag("obfuscation")) {
      findings.push(makeFinding(ctx.findingCounter.value++, {
        rule_id: "META-PERSISTENT-COMPROMISE",
        severity: "CRITICAL",
        confidence: 0.9,
        title: "Obfuscated cognitive file tampering detected",
        description:
          "Plugin uses obfuscation techniques alongside cognitive file modification. " +
          "This suggests an attempt to covertly alter agent identity or behaviour for " +
          "persistent compromise (T4 threat class).",
        remediation: "Block this plugin. Inspect cognitive files for unauthorized changes.",
        tags: ["cognitive-tampering", "obfuscation"],
      }));
    }

    // Chain: SSRF/metadata + credential access = cloud credential theft
    const hasSSRF = hasRule("SSRF-AWS-META") || hasRule("SSRF-GCP-META") ||
                    hasRule("SSRF-AZURE-META");
    if (hasSSRF && hasCreds) {
      findings.push(makeFinding(ctx.findingCounter.value++, {
        rule_id: "META-CLOUD-CRED-THEFT",
        severity: "CRITICAL",
        confidence: 0.9,
        title: "Cloud credential theft pattern: SSRF + credential access",
        description:
          "Plugin accesses cloud metadata endpoints and reads credential files. " +
          "This pattern enables stealing IAM tokens and API keys from cloud instances.",
        remediation: "Block this plugin. Review for lateral movement attempts.",
        tags: ["exfiltration", "credential-theft"],
      }));
    }

    // LLM-powered meta analysis (when configured)
    if (this.llmPolicy?.enabled) {
      try {
        const { runMetaLLM } = await import("./llm_analyzer.js");
        const llmConfig = {
          model: this.llmPolicy.model,
          apiKey: this.llmPolicy.api_key || undefined,
          apiBase: this.llmPolicy.api_base || undefined,
          provider: this.llmPolicy.provider || undefined,
          maxTokens: this.llmPolicy.max_output_tokens,
          pythonBinary: this.llmPolicy.python_binary || undefined,
        };

        const { newFindings, falsePositiveRuleIds } = await runMetaLLM(llmConfig, ctx);
        findings.push(...newFindings);

        // Mark false positives as suppressed in previous findings
        // (they stay in the output but with suppressed=true)
        if (falsePositiveRuleIds.length > 0) {
          for (const f of prev) {
            if (f.rule_id && falsePositiveRuleIds.includes(f.rule_id)) {
              f.suppressed = true;
              f.suppression_reason = "LLM meta-analysis: likely false positive";
            }
          }
        }
      } catch {
        // LLM meta not available — pattern-based findings are still returned
      }
    }

    return findings;
  }
}
