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
 * Scan-phase functions for the plugin scanner.
 *
 * Each exported function analyses one aspect of a plugin (manifest checks,
 * source-code patterns, directory structure) and pushes findings into the
 * shared findings array.
 */
import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { Finding, PluginManifest, Severity, ToolManifest, ScanProfile } from "../../types.js";
import {
  DANGEROUS_PERMISSIONS,
  RISKY_DEPENDENCIES,
  DANGEROUS_INSTALL_SCRIPTS,
  SHELL_COMMANDS_IN_SCRIPTS,
  C2_DOMAINS,
  COGNITIVE_FILES,
  BINARY_EXTENSIONS,
  SCRIPT_EXTENSIONS,
  SAFE_DOTFILES,
  SOURCE_PATTERN_RULES,
  SECRET_PATTERNS,
  CREDENTIAL_PATH_PATTERNS,
  GATEWAY_PATTERNS,
  WRITE_FUNCTIONS,
  CLOUD_METADATA_PATTERNS,
  PRIVATE_IP_PATTERN,
  INTERNAL_HOSTNAME_PATTERNS,
  DYNAMIC_IMPORT_PATTERNS,
  BUNDLE_SIZE_THRESHOLD_BYTES,
  BUNDLE_DIRS,
  JSON_SECRET_PATTERNS,
  JSON_URL_PATTERNS,
} from "./rules.js";
import {
  makeFinding,
  stripComment,
  isCommentLine,
  isTestPath,
  downgrade,
  collectFiles,
  sanitiseEvidence,
} from "./helpers.js";

// ---------------------------------------------------------------------------
// Manifest checks
// ---------------------------------------------------------------------------

export function checkPermissions(
  manifest: PluginManifest,
  findings: Finding[],
  target: string,
): void {
  if (!manifest.permissions || manifest.permissions.length === 0) {
    findings.push(makeFinding(findings.length + 1, {
      rule_id: "PERM-NONE",
      severity: "LOW",
      confidence: 1.0,
      title: "Plugin declares no permissions",
      description:
        "No permissions declared in manifest. The plugin may operate without " +
        "restrictions, or permissions may not be documented.",
      location: `${target}/${manifest.source ?? "package.json"}`,
      remediation:
        "Declare required permissions explicitly in the manifest to enable policy enforcement.",
    }));
    return;
  }

  for (const perm of manifest.permissions) {
    if (DANGEROUS_PERMISSIONS.has(perm)) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "PERM-DANGEROUS",
        severity: "HIGH",
        confidence: 0.95,
        title: `Dangerous permission: ${perm}`,
        evidence: `"permissions": ["${perm}"]`,
        description:
          `Plugin requests "${perm}" which grants broad ${perm.split(":")[0]} access. ` +
          "This permission should be scoped more narrowly.",
        location: `${target}/${manifest.source ?? "package.json"}`,
        remediation: `Replace "${perm}" with specific, scoped permissions (e.g., "fs:read:/specific/path").`,
      }));
    } else if (perm.endsWith(":*")) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "PERM-WILDCARD",
        severity: "MEDIUM",
        confidence: 0.8,
        title: `Wildcard permission: ${perm}`,
        evidence: `"permissions": ["${perm}"]`,
        description:
          `Plugin uses wildcard permission "${perm}". Wildcard permissions bypass fine-grained policy enforcement.`,
        location: `${target}/${manifest.source ?? "package.json"}`,
        remediation: "Use specific, scoped permissions instead of wildcards.",
      }));
    }
  }
}

export function checkDependencies(
  manifest: PluginManifest,
  findings: Finding[],
  target: string,
): void {
  if (!manifest.dependencies) return;

  for (const dep of Object.keys(manifest.dependencies)) {
    if (RISKY_DEPENDENCIES.has(dep)) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "DEP-RISKY",
        severity: "MEDIUM",
        confidence: 0.75,
        title: `Risky dependency: ${dep}`,
        evidence: `"${dep}": "${manifest.dependencies[dep]}"`,
        description: `Plugin depends on "${dep}" which can execute arbitrary commands or code.`,
        location: `${target}/${manifest.source ?? "package.json"}`,
        remediation: `Review usage of "${dep}" and ensure it does not process untrusted input.`,
        tags: ["supply-chain"],
      }));
    }
  }

  for (const [dep, version] of Object.entries(manifest.dependencies)) {
    if (typeof version !== "string") continue;

    if (version === "*" || version === "latest" || version === "") {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "DEP-UNPINNED",
        severity: "MEDIUM",
        confidence: 0.9,
        title: `Unpinned dependency: ${dep}@${version || "(empty)"}`,
        evidence: `"${dep}": "${version}"`,
        description: `Dependency "${dep}" uses unpinned version "${version || "(empty)"}". Unpinned versions are vulnerable to dependency confusion attacks.`,
        location: `${target}/${manifest.source ?? "package.json"}`,
        remediation: `Pin "${dep}" to a specific version or range (e.g., "^1.2.3").`,
        tags: ["supply-chain"],
      }));
    }

    if (version.startsWith("http://")) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "DEP-HTTP",
        severity: "HIGH",
        confidence: 0.95,
        title: `Dependency "${dep}" fetched over HTTP`,
        evidence: `"${dep}": "${version}"`,
        description: `Dependency "${dep}" uses an unencrypted HTTP URL, allowing man-in-the-middle package substitution.`,
        location: `${target}/${manifest.source ?? "package.json"}`,
        remediation: "Use HTTPS or a registry reference instead.",
        tags: ["supply-chain"],
      }));
    }

    if (version.startsWith("file:")) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "DEP-LOCAL-FILE",
        severity: "MEDIUM",
        confidence: 0.7,
        title: `Dependency "${dep}" uses local file path`,
        evidence: `"${dep}": "${version}"`,
        description: `Dependency "${dep}" references a local file path ("${version}"). This may be a path-traversal vector.`,
        location: `${target}/${manifest.source ?? "package.json"}`,
        remediation: "Use a registry-published package instead of a local file reference.",
        tags: ["supply-chain"],
      }));
    }

    if (version.startsWith("git") || version.startsWith("github:")) {
      if (!/#[a-f0-9]{7,}/.test(version)) {
        findings.push(makeFinding(findings.length + 1, {
          rule_id: "DEP-GIT-UNPIN",
          severity: "MEDIUM",
          confidence: 0.85,
          title: `Git dependency "${dep}" without commit pin`,
          evidence: `"${dep}": "${version}"`,
          description: `Dependency "${dep}" references a git source without a commit hash. The content can change silently.`,
          location: `${target}/${manifest.source ?? "package.json"}`,
          remediation: `Pin "${dep}" to a specific commit hash (e.g., "github:user/repo#abc1234").`,
          tags: ["supply-chain"],
        }));
      }
    }
  }
}

export function checkInstallScripts(
  manifest: PluginManifest,
  findings: Finding[],
  target: string,
): void {
  if (!manifest.scripts) return;

  for (const [name, value] of Object.entries(manifest.scripts)) {
    if (typeof value !== "string") continue;

    if (DANGEROUS_INSTALL_SCRIPTS.has(name)) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "SCRIPT-INSTALL-HOOK",
        severity: "HIGH",
        confidence: 0.9,
        title: `Dangerous install script: ${name}`,
        evidence: `"${name}": "${value.slice(0, 120)}"`,
        description:
          `Plugin defines a "${name}" script that runs automatically during npm install. ` +
          "Install scripts are a primary npm supply-chain attack vector.",
        location: `${target}/${manifest.source ?? "package.json"} → scripts.${name}`,
        remediation:
          `Remove the "${name}" script or replace with explicit build steps that users run manually.`,
        tags: ["supply-chain"],
      }));
    }

    if (SHELL_COMMANDS_IN_SCRIPTS.test(value)) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "SCRIPT-SHELL-CMD",
        severity: "MEDIUM",
        confidence: 0.8,
        title: `Script "${name}" invokes shell commands`,
        evidence: `"${name}": "${value.slice(0, 120)}"`,
        description:
          `The "${name}" script contains shell command invocations (${value.slice(0, 80)}). ` +
          "Scripts that download or execute external code introduce supply-chain risk.",
        location: `${target}/${manifest.source ?? "package.json"} → scripts.${name}`,
        remediation: "Review the script and remove unnecessary shell invocations.",
        tags: ["supply-chain"],
      }));
    }
  }
}

export function hasInstallScripts(manifest: PluginManifest): boolean {
  if (!manifest.scripts) return false;
  return Object.keys(manifest.scripts).some((k) => DANGEROUS_INSTALL_SCRIPTS.has(k));
}

export function checkTool(
  tool: ToolManifest,
  findings: Finding[],
  target: string,
): void {
  if (!tool.description) {
    findings.push(makeFinding(findings.length + 1, {
      rule_id: "TOOL-NO-DESC",
      severity: "LOW",
      confidence: 1.0,
      title: `Tool "${tool.name}" lacks description`,
      description:
        "Tools without descriptions cannot be reviewed for safety by users or automated systems.",
      location: `${target} → tool:${tool.name}`,
      remediation: "Add a clear description explaining what this tool does.",
    }));
  }

  if (tool.permissions) {
    for (const perm of tool.permissions) {
      if (DANGEROUS_PERMISSIONS.has(perm)) {
        findings.push(makeFinding(findings.length + 1, {
          rule_id: "TOOL-PERM-DANGEROUS",
          severity: "HIGH",
          confidence: 0.95,
          title: `Tool "${tool.name}" requests dangerous permission: ${perm}`,
          evidence: `tool "${tool.name}" → permissions: ["${perm}"]`,
          description: `Tool "${tool.name}" requests "${perm}" which grants broad system access.`,
          location: `${target} → tool:${tool.name}`,
          remediation: `Scope the permission for tool "${tool.name}" more narrowly.`,
        }));
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Source file scanning
// ---------------------------------------------------------------------------

export async function scanSourceFiles(
  dir: string,
  findings: Finding[],
  capabilities: Set<string>,
  profile: ScanProfile,
): Promise<{ fileCount: number; totalBytes: number }> {
  const tsFiles = await collectFiles(dir, [".ts", ".js", ".mjs"]);
  let totalBytes = 0;

  for (const file of tsFiles) {
    let content: string;
    try {
      content = await readFile(file, "utf-8");
    } catch {
      continue;
    }

    totalBytes += content.length;
    if (content.length > 512 * 1024) continue;

    const relPath = file.replace(dir + "/", "");
    const inTestPath = isTestPath(relPath);
    const lines = content.split("\n");
    const codeLines = lines.map(stripComment);

    scanSuspiciousPatterns(codeLines, relPath, findings, capabilities, profile, inTestPath);
    checkForHardcodedSecrets(lines, relPath, findings, inTestPath);
    checkForCredentialAccess(codeLines, relPath, findings, capabilities, inTestPath);
    checkForExfiltration(lines, content, relPath, findings, capabilities, inTestPath);
    checkForSSRF(codeLines, relPath, findings, inTestPath);
    checkForDynamicImports(codeLines, relPath, findings, inTestPath);
    checkForCognitiveFileTampering(codeLines, content, relPath, findings);
    checkForObfuscation(codeLines, content, relPath, findings, inTestPath);
    checkForGatewayManipulation(codeLines, lines, relPath, findings, inTestPath);
    checkForCostRunaway(codeLines, relPath, findings);
  }

  return { fileCount: tsFiles.length, totalBytes };
}

function scanSuspiciousPatterns(
  codeLines: string[],
  relPath: string,
  findings: Finding[],
  capabilities: Set<string>,
  profile: ScanProfile,
  inTestPath: boolean,
): void {
  for (const rule of SOURCE_PATTERN_RULES) {
    if (!rule.profiles.includes(profile)) continue;

    for (let i = 0; i < codeLines.length; i++) {
      if (rule.pattern.test(codeLines[i])) {
        if (rule.capability) capabilities.add(rule.capability);
        if (inTestPath && rule.severity === "INFO") break;

        findings.push(makeFinding(findings.length + 1, {
          rule_id: rule.id,
          severity: inTestPath ? downgrade(rule.severity) : rule.severity,
          confidence: inTestPath ? rule.confidence * 0.5 : rule.confidence,
          title: rule.title,
          evidence: sanitiseEvidence(codeLines[i]),
          description: "Detected in source file. Review for secure usage.",
          location: `${relPath}:${i + 1}`,
          remediation: "Ensure this pattern is used safely and does not process untrusted input.",
          tags: rule.tags,
        }));
        break;
      }
    }
  }
}

function checkForHardcodedSecrets(
  lines: string[],
  relPath: string,
  findings: Finding[],
  inTestPath: boolean,
): void {
  for (const { id, pattern, title, confidence } of SECRET_PATTERNS) {
    const lineIdx = lines.findIndex((l) => pattern.test(l));
    if (lineIdx >= 0) {
      const effectiveSeverity: Severity = inTestPath ? "MEDIUM" : "CRITICAL";
      const effectiveConfidence = inTestPath ? confidence * 0.4 : confidence;

      findings.push(makeFinding(findings.length + 1, {
        rule_id: id,
        severity: effectiveSeverity,
        confidence: effectiveConfidence,
        title: inTestPath ? `${title} (in test file)` : title,
        evidence: sanitiseEvidence(lines[lineIdx], true),
        description:
          inTestPath
            ? "Possible credential detected in a test file. Verify it is a placeholder and not a live secret."
            : "Hardcoded credential detected in plugin source code. Credentials in source should be rotated immediately.",
        location: `${relPath}:${lineIdx + 1}`,
        remediation:
          "Remove the credential from source code. Use environment variables or a secrets manager.",
        tags: ["credential-theft"],
      }));
    }
  }
}

function checkForCredentialAccess(
  codeLines: string[],
  relPath: string,
  findings: Finding[],
  capabilities: Set<string>,
  inTestPath: boolean,
): void {
  for (const { id, pattern, title } of CREDENTIAL_PATH_PATTERNS) {
    for (let i = 0; i < codeLines.length; i++) {
      if (pattern.test(codeLines[i])) {
        capabilities.add("credential-access");
        if (inTestPath) break;

        findings.push(makeFinding(findings.length + 1, {
          rule_id: id,
          severity: "HIGH",
          confidence: 0.9,
          title,
          evidence: sanitiseEvidence(codeLines[i]),
          description:
            "Plugin accesses sensitive credential paths. A compromised plugin " +
            "with credential access can exfiltrate API keys and tokens.",
          location: `${relPath}:${i + 1}`,
          remediation:
            "Plugins should not access credential files directly. " +
            "Use the PluginContext API for authorised access.",
          tags: ["credential-theft"],
        }));
        break;
      }
    }
  }
}

function checkForExfiltration(
  lines: string[],
  content: string,
  relPath: string,
  findings: Finding[],
  capabilities: Set<string>,
  inTestPath: boolean,
): void {
  for (const domain of C2_DOMAINS) {
    const idx = lines.findIndex((l) => l.includes(domain));
    if (idx >= 0) {
      capabilities.add("network");
      const inComment = isCommentLine(lines[idx]);
      const effectiveSeverity: Severity = (inTestPath || inComment) ? "MEDIUM" : "CRITICAL";
      const effectiveConfidence = (inTestPath || inComment) ? 0.4 : 0.95;

      findings.push(makeFinding(findings.length + 1, {
        rule_id: "EXFIL-C2-DOMAIN",
        severity: effectiveSeverity,
        confidence: effectiveConfidence,
        title: `Known exfiltration domain: ${domain}`,
        evidence: sanitiseEvidence(lines[idx]),
        description:
          (inTestPath || inComment)
            ? `Reference to "${domain}" found in ${inTestPath ? "test file" : "comment"}. Verify this is documentation or a test fixture, not active exfiltration code.`
            : `Plugin references "${domain}", a known data-exfiltration/C2 service. This is a strong indicator of data exfiltration.`,
        location: `${relPath}:${idx + 1}`,
        remediation: "Remove the reference and investigate the plugin's provenance.",
        tags: ["exfiltration"],
      }));
    }
  }

  if (/\bdns\.resolve\b|\bdns\.lookup\b/.test(content) &&
      /process\.env|readFile|credentials/.test(content)) {
    findings.push(makeFinding(findings.length + 1, {
      rule_id: "EXFIL-DNS",
      severity: inTestPath ? "MEDIUM" : "HIGH",
      confidence: inTestPath ? 0.4 : 0.85,
      title: "Possible DNS exfiltration pattern",
      evidence: "dns.resolve/dns.lookup combined with credential/env access",
      description:
        "Plugin uses DNS resolution combined with credential/env access. " +
        "DNS queries can encode data in subdomains for exfiltration.",
      location: relPath,
      remediation: "Review DNS usage and ensure it is not used for data exfiltration.",
      tags: ["exfiltration"],
    }));
  }
}

function checkForCognitiveFileTampering(
  codeLines: string[],
  content: string,
  relPath: string,
  findings: Finding[],
): void {
  for (const cogFile of COGNITIVE_FILES) {
    if (!content.includes(cogFile)) continue;
    const hasWrite = WRITE_FUNCTIONS.test(content);
    if (!hasWrite) continue;

    const lineIdx = codeLines.findIndex((l) => l.includes(cogFile));
    if (lineIdx < 0) continue;

    findings.push(makeFinding(findings.length + 1, {
      rule_id: "COG-TAMPER",
      severity: "HIGH",
      confidence: 0.9,
      title: `Possible cognitive file tampering: ${cogFile}`,
      evidence: sanitiseEvidence(codeLines[lineIdx]),
      description:
        `Plugin references "${cogFile}" and contains file-write operations. ` +
        "Modifying OpenClaw cognitive files persists behavioral changes across all sessions, " +
        "enabling long-term agent compromise (T4 threat class).",
      location: `${relPath}:${lineIdx + 1}`,
      remediation:
        `Plugins must not write to "${cogFile}". ` +
        "Agent identity and behaviour files should only be modified by the operator.",
      tags: ["cognitive-tampering"],
    }));
  }
}

function checkForObfuscation(
  codeLines: string[],
  _content: string,
  relPath: string,
  findings: Finding[],
  inTestPath: boolean,
): void {
  const codeContent = codeLines.join("\n");

  for (let i = 0; i < codeLines.length; i++) {
    if (/Buffer\.from\s*\(\s*["'][A-Za-z0-9+/=]{50,}["']/.test(codeLines[i]) ||
        /\batob\s*\(\s*["'][A-Za-z0-9+/=]{50,}["']/.test(codeLines[i])) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "OBF-BASE64",
        severity: inTestPath ? "LOW" : "MEDIUM",
        confidence: inTestPath ? 0.3 : 0.7,
        title: "Base64-encoded payload detected",
        evidence: sanitiseEvidence(codeLines[i]),
        description:
          "Plugin decodes a large base64 string at runtime. " +
          "Base64 encoding is commonly used to hide URLs, shell commands, or credentials.",
        location: `${relPath}:${i + 1}`,
        remediation: "Decode and review the base64 payload. Remove if it contains suspicious content.",
        tags: ["obfuscation"],
      }));
      break;
    }
  }

  if (/String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){4,}/.test(codeContent)) {
    const idx = codeLines.findIndex((l) => /String\.fromCharCode/.test(l));
    findings.push(makeFinding(findings.length + 1, {
      rule_id: "OBF-CHARCODE",
      severity: "MEDIUM",
      confidence: 0.8,
      title: "String.fromCharCode obfuscation detected",
      evidence: idx >= 0 ? sanitiseEvidence(codeLines[idx]) : undefined,
      description:
        "Plugin constructs strings from character codes, a technique used to evade static analysis.",
      location: `${relPath}:${idx >= 0 ? idx + 1 : 0}`,
      remediation: "Evaluate the constructed string and replace with a readable literal if safe.",
      tags: ["obfuscation"],
    }));
  }

  if (/(?:\\x[0-9a-fA-F]{2}){4,}/.test(codeContent)) {
    const idx = codeLines.findIndex((l) => /(?:\\x[0-9a-fA-F]{2}){4,}/.test(l));
    findings.push(makeFinding(findings.length + 1, {
      rule_id: "OBF-HEX",
      severity: "MEDIUM",
      confidence: 0.75,
      title: "Hex escape sequence obfuscation detected",
      evidence: idx >= 0 ? sanitiseEvidence(codeLines[idx]) : undefined,
      description:
        "Plugin uses hex escape sequences to build strings, a common technique for hiding commands.",
      location: `${relPath}:${idx >= 0 ? idx + 1 : 0}`,
      remediation: "Decode the hex sequence and review the resulting string.",
      tags: ["obfuscation"],
    }));
  }

  const concatEvasion = /['"](?:ev|cu|ch|ex|sp)['"]\s*\+\s*['"](?:al|rl|ild|ec|awn)/;
  if (concatEvasion.test(codeContent)) {
    const idx = codeLines.findIndex((l) => concatEvasion.test(l));
    findings.push(makeFinding(findings.length + 1, {
      rule_id: "OBF-CONCAT",
      severity: "HIGH",
      confidence: 0.9,
      title: "String concatenation evasion detected",
      evidence: idx >= 0 ? sanitiseEvidence(codeLines[idx]) : undefined,
      description:
        "Plugin splits a dangerous function name across string concatenation to evade static analysis. " +
        "This is a strong indicator of intentional evasion.",
      location: `${relPath}:${idx >= 0 ? idx + 1 : 0}`,
      remediation: "Investigate the plugin immediately — this pattern is rarely legitimate.",
      tags: ["obfuscation"],
    }));
  }

  if (codeLines.length > 0 && codeLines.length < 20) {
    const totalLen = codeLines.reduce((sum, l) => sum + l.length, 0);
    const avgLen = totalLen / codeLines.length;
    if (avgLen > 500 && totalLen > 10_000) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "OBF-MINIFIED",
        severity: "INFO",
        confidence: 0.6,
        title: "Minified or bundled code detected",
        description:
          "Source file appears to be minified or bundled (very long lines, few line breaks). " +
          "Minified code is difficult to audit for security issues.",
        location: relPath,
        remediation: "Request unminified source for security review, or use a deobfuscation tool.",
        tags: ["obfuscation"],
      }));
    }
  }
}

function checkForGatewayManipulation(
  codeLines: string[],
  rawLines: string[],
  relPath: string,
  findings: Finding[],
  inTestPath: boolean,
): void {
  for (const { id, pattern, title, severity, confidence } of GATEWAY_PATTERNS) {
    for (let i = 0; i < codeLines.length; i++) {
      if (pattern.test(codeLines[i])) {
        findings.push(makeFinding(findings.length + 1, {
          rule_id: id,
          severity: inTestPath ? downgrade(severity) : severity,
          confidence: inTestPath ? confidence * 0.5 : confidence,
          title,
          evidence: sanitiseEvidence(rawLines[i]),
          description:
            "Plugin interacts with gateway internals or modifies the runtime environment. " +
            "This can crash the gateway, hijack the module system, or pollute prototypes (T5 threat class).",
          location: `${relPath}:${i + 1}`,
          remediation:
            "Plugins should not modify the runtime environment. " +
            "Use the PluginContext API for authorised interactions.",
          tags: ["gateway-manipulation"],
        }));
        break;
      }
    }
  }
}

function checkForCostRunaway(
  codeLines: string[],
  relPath: string,
  findings: Finding[],
): void {
  for (let i = 0; i < codeLines.length; i++) {
    const match = codeLines[i].match(/setInterval\s*\([^,]+,\s*(\d+)\s*\)/);
    if (match) {
      const interval = parseInt(match[1], 10);
      if (interval < 1000) {
        const nearbyLines = codeLines.slice(Math.max(0, i - 5), i + 10).join("\n");
        if (/\b(?:fetch|http|https|request|openai|anthropic|api)\b/i.test(nearbyLines)) {
          findings.push(makeFinding(findings.length + 1, {
            rule_id: "COST-RUNAWAY",
            severity: "MEDIUM",
            confidence: 0.75,
            title: "Possible cost runaway: rapid API polling",
            evidence: sanitiseEvidence(codeLines[i]),
            description:
              `Plugin uses setInterval with ${interval}ms delay near API/network calls. ` +
              "This pattern can cause runaway API costs or rate-limit exhaustion (T7 threat class).",
            location: `${relPath}:${i + 1}`,
            remediation: "Use reasonable polling intervals (≥ 1 second) and implement backoff.",
            tags: ["cost-runaway"],
          }));
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Directory structure scanning
// ---------------------------------------------------------------------------

export async function scanDirectoryStructure(
  dir: string,
  findings: Finding[],
): Promise<void> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry === "node_modules" || entry === "dist") continue;

    const ext = entry.lastIndexOf(".") >= 0 ? entry.slice(entry.lastIndexOf(".")) : "";

    if (entry === ".env" || entry === ".env.local" || entry === ".env.production") {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "STRUCT-ENV-FILE",
        severity: "CRITICAL",
        confidence: 0.95,
        title: `Environment file found: ${entry}`,
        evidence: `File: ${entry}`,
        description:
          "Plugin directory contains an environment file that likely holds secrets. " +
          "Secrets in a plugin directory risk being published or accessed by other plugins.",
        location: `${dir}/${entry}`,
        remediation: "Remove the .env file and use a secrets manager or environment variables instead.",
        tags: ["credential-theft"],
      }));
    } else if (BINARY_EXTENSIONS.has(ext)) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "STRUCT-BINARY",
        severity: "HIGH",
        confidence: 0.9,
        title: `Binary executable found: ${entry}`,
        evidence: `File: ${entry}`,
        description:
          `Plugin contains a binary file "${entry}". Binary executables cannot be audited ` +
          "for security and may contain malware.",
        location: `${dir}/${entry}`,
        remediation: "Remove binary files. Plugins should contain only auditable source code.",
        tags: ["supply-chain"],
      }));
    } else if (SCRIPT_EXTENSIONS.has(ext)) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "STRUCT-SCRIPT",
        severity: "LOW",
        confidence: 0.6,
        title: `Script file found: ${entry}`,
        evidence: `File: ${entry}`,
        description:
          `Plugin contains a script file "${entry}". While auditable, script files ` +
          "can execute arbitrary commands if invoked during install or build.",
        location: `${dir}/${entry}`,
        remediation: "Review the script contents. Ensure it is not invoked by install hooks.",
        tags: ["supply-chain"],
      }));
    } else if (entry.startsWith(".") && !SAFE_DOTFILES.has(entry)) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "STRUCT-HIDDEN",
        severity: "LOW",
        confidence: 0.5,
        title: `Hidden file found: ${entry}`,
        evidence: `File: ${entry}`,
        description: `Plugin contains hidden file "${entry}" which may conceal configuration or data.`,
        location: `${dir}/${entry}`,
        remediation: "Review the hidden file and remove if unnecessary.",
      }));
    }
  }
}

// ---------------------------------------------------------------------------
// SSRF / Cloud metadata detection
// ---------------------------------------------------------------------------

function checkForSSRF(
  codeLines: string[],
  relPath: string,
  findings: Finding[],
  inTestPath: boolean,
): void {
  // Cloud metadata endpoints
  for (const { id, pattern, title, confidence } of CLOUD_METADATA_PATTERNS) {
    for (let i = 0; i < codeLines.length; i++) {
      if (pattern.test(codeLines[i])) {
        findings.push(makeFinding(findings.length + 1, {
          rule_id: id,
          severity: inTestPath ? "MEDIUM" : "HIGH",
          confidence: inTestPath ? confidence * 0.5 : confidence,
          title,
          evidence: sanitiseEvidence(codeLines[i]),
          description:
            "Plugin references a cloud metadata endpoint. " +
            "SSRF attacks use metadata endpoints to steal IAM credentials, tokens, and instance configuration.",
          location: `${relPath}:${i + 1}`,
          remediation: "Remove the metadata endpoint reference. Plugins should not access cloud instance metadata.",
          tags: ["exfiltration"],
        }));
        break;
      }
    }
  }

  // Private IP addresses in network contexts
  for (let i = 0; i < codeLines.length; i++) {
    const line = codeLines[i];
    if (PRIVATE_IP_PATTERN.test(line) && /\b(?:fetch|http|request|get|post|url|endpoint|host)\b/i.test(line)) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "SSRF-PRIVATE-IP",
        severity: inTestPath ? "LOW" : "MEDIUM",
        confidence: inTestPath ? 0.3 : 0.65,
        title: "Private IP address in network context",
        evidence: sanitiseEvidence(line),
        description:
          "Plugin references a private/internal IP address alongside network operations. " +
          "This may indicate SSRF or lateral movement attempts.",
        location: `${relPath}:${i + 1}`,
        remediation: "Remove hardcoded internal IPs. Use configuration or service discovery instead.",
        tags: ["exfiltration"],
      }));
      break;
    }
  }

  // Internal hostnames in network calls
  for (let i = 0; i < codeLines.length; i++) {
    if (INTERNAL_HOSTNAME_PATTERNS.test(codeLines[i])) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "SSRF-INTERNAL-HOST",
        severity: inTestPath ? "LOW" : "MEDIUM",
        confidence: inTestPath ? 0.25 : 0.55,
        title: "Internal hostname in network context",
        evidence: sanitiseEvidence(codeLines[i]),
        description:
          "Plugin references an internal hostname (localhost, corp, internal, etc.) in a network call.",
        location: `${relPath}:${i + 1}`,
        remediation: "Verify the hostname is intentional and not an SSRF target.",
        tags: ["exfiltration"],
      }));
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Dynamic import / require / spawn detection
// ---------------------------------------------------------------------------

function checkForDynamicImports(
  codeLines: string[],
  relPath: string,
  findings: Finding[],
  inTestPath: boolean,
): void {
  for (const { id, pattern, title, severity, confidence } of DYNAMIC_IMPORT_PATTERNS) {
    for (let i = 0; i < codeLines.length; i++) {
      if (pattern.test(codeLines[i])) {
        findings.push(makeFinding(findings.length + 1, {
          rule_id: id,
          severity: inTestPath ? downgrade(severity) : severity,
          confidence: inTestPath ? confidence * 0.5 : confidence,
          title,
          evidence: sanitiseEvidence(codeLines[i]),
          description:
            "Plugin uses a dynamic import, require, or process spawn with a non-literal argument. " +
            "This can load arbitrary code at runtime, bypassing static analysis.",
          location: `${relPath}:${i + 1}`,
          remediation: "Use string-literal module specifiers. If dynamic loading is needed, validate the argument against an allowlist.",
          tags: ["code-execution"],
        }));
        break;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// OpenClaw plugin manifest scanning
// ---------------------------------------------------------------------------

export async function scanClawManifest(
  dir: string,
  findings: Finding[],
): Promise<void> {
  let raw: string;
  try {
    raw = await readFile(join(dir, "openclaw.plugin.json"), "utf-8");
  } catch {
    return; // no openclaw manifest — not an error, package.json is the primary
  }

  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    findings.push(makeFinding(findings.length + 1, {
      rule_id: "CLAW-MANIFEST-MISSING",
      severity: "MEDIUM",
      confidence: 1.0,
      title: "Malformed openclaw.plugin.json",
      evidence: "File exists but is not valid JSON",
      description: "The openclaw.plugin.json file exists but could not be parsed as JSON.",
      location: `${dir}/openclaw.plugin.json`,
      remediation: "Fix the JSON syntax in openclaw.plugin.json.",
      tags: ["supply-chain"],
    }));
    return;
  }

  // Check for dangerous hooks
  const hooks = manifest["hooks"] as Record<string, unknown> | undefined;
  if (hooks && typeof hooks === "object") {
    const dangerousHooks = ["onInstall", "onLoad", "onEnable"];
    for (const hookName of dangerousHooks) {
      const hookValue = hooks[hookName];
      if (typeof hookValue === "string" && hookValue.length > 0) {
        findings.push(makeFinding(findings.length + 1, {
          rule_id: "CLAW-HOOK-DANGEROUS",
          severity: "MEDIUM",
          confidence: 0.8,
          title: `Plugin declares lifecycle hook: ${hookName}`,
          evidence: `"${hookName}": "${String(hookValue).slice(0, 120)}"`,
          description:
            `Plugin registers a "${hookName}" lifecycle hook that executes automatically. ` +
            "Lifecycle hooks can run arbitrary code during plugin installation or loading.",
          location: `${dir}/openclaw.plugin.json → hooks.${hookName}`,
          remediation: `Review the "${hookName}" hook. Ensure it does not execute untrusted code.`,
          tags: ["supply-chain"],
        }));
      }
    }
  }

  // Check tools declared in openclaw.plugin.json
  const tools = manifest["tools"] as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(tools)) {
    for (const tool of tools) {
      if (!tool["description"] && tool["name"]) {
        findings.push(makeFinding(findings.length + 1, {
          rule_id: "CLAW-TOOL-NO-DESC",
          severity: "LOW",
          confidence: 1.0,
          title: `OpenClaw tool "${tool["name"]}" lacks description`,
          description:
            "Tools declared in openclaw.plugin.json without descriptions cannot be reviewed by users or admission gates.",
          location: `${dir}/openclaw.plugin.json → tools`,
          remediation: "Add a description to every tool declared in the plugin manifest.",
        }));
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Bundle / dist size detection
// ---------------------------------------------------------------------------

export async function scanBundleSize(
  dir: string,
  findings: Finding[],
): Promise<void> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return;
  }

  for (const entry of entries) {
    if (!BUNDLE_DIRS.has(entry)) continue;

    const bundlePath = join(dir, entry);
    try {
      const info = await stat(bundlePath);
      if (!info.isDirectory()) continue;
    } catch {
      continue;
    }

    const totalSize = await measureDirSize(bundlePath);
    if (totalSize > BUNDLE_SIZE_THRESHOLD_BYTES) {
      const sizeMB = (totalSize / (1024 * 1024)).toFixed(1);
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "STRUCT-LARGE-BUNDLE",
        severity: "MEDIUM",
        confidence: 0.7,
        title: `Large bundle directory: ${entry}/ (${sizeMB} MB)`,
        evidence: `${entry}/ — ${sizeMB} MB (threshold: ${(BUNDLE_SIZE_THRESHOLD_BYTES / 1024 / 1024).toFixed(0)} MB)`,
        description:
          `Plugin contains a ${sizeMB} MB "${entry}" directory. Large bundled/compiled artifacts ` +
          "cannot be effectively audited for security and may hide malicious code.",
        location: `${dir}/${entry}`,
        remediation: "Ship source code instead of bundles, or provide source maps and unminified source for review.",
        tags: ["obfuscation"],
      }));
    }
  }
}

async function measureDirSize(dir: string, maxDepth = 3, depth = 0): Promise<number> {
  if (depth >= maxDepth) return 0;
  let total = 0;
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return 0;
  }
  for (const entry of entries) {
    const fullPath = join(dir, entry);
    try {
      const info = await stat(fullPath);
      if (info.isDirectory()) {
        total += await measureDirSize(fullPath, maxDepth, depth + 1);
      } else {
        total += info.size;
      }
    } catch {
      continue;
    }
  }
  return total;
}

// ---------------------------------------------------------------------------
// JSON config artifact scanning
// ---------------------------------------------------------------------------

export async function scanJsonConfigs(
  dir: string,
  findings: Finding[],
): Promise<void> {
  const jsonFiles = await collectFiles(dir, [".json"], 3);

  for (const file of jsonFiles) {
    const basename = file.split("/").pop() ?? "";
    // Skip package.json (already handled), lockfiles, and tsconfig
    if (basename === "package.json" || basename === "package-lock.json" ||
        basename === "tsconfig.json" || basename === "openclaw.plugin.json") continue;

    let content: string;
    try {
      content = await readFile(file, "utf-8");
    } catch {
      continue;
    }

    if (content.length > 256 * 1024) continue; // skip very large JSON
    const relPath = file.replace(dir + "/", "");

    // Check for secrets in JSON values
    for (const { id, pattern, title, confidence } of JSON_SECRET_PATTERNS) {
      const match = pattern.exec(content);
      if (match) {
        const lineIdx = content.slice(0, match.index).split("\n").length;
        findings.push(makeFinding(findings.length + 1, {
          rule_id: id,
          severity: "HIGH",
          confidence,
          title: `${title}: ${relPath}`,
          evidence: sanitiseEvidence(match[0], true),
          description:
            "JSON configuration file contains a possible secret or credential. " +
            "Secrets in config files risk being committed to version control or published.",
          location: `${relPath}:${lineIdx}`,
          remediation: "Move secrets to environment variables or a secrets manager. Do not store them in JSON config files.",
          tags: ["credential-theft"],
        }));
      }
    }

    // Check for suspicious URLs
    for (const { id, pattern, title, confidence } of JSON_URL_PATTERNS) {
      const match = pattern.exec(content);
      if (match) {
        const lineIdx = content.slice(0, match.index).split("\n").length;
        findings.push(makeFinding(findings.length + 1, {
          rule_id: id,
          severity: id === "JSON-URL-C2" ? "CRITICAL" : "HIGH",
          confidence,
          title: `${title}: ${relPath}`,
          evidence: sanitiseEvidence(match[0]),
          description:
            id === "JSON-URL-C2"
              ? "JSON config file contains a URL pointing to a known C2/exfiltration service."
              : "JSON config file contains a URL pointing to a cloud metadata endpoint or localhost.",
          location: `${relPath}:${lineIdx}`,
          remediation: "Remove the suspicious URL from the config file.",
          tags: id === "JSON-URL-C2" ? ["exfiltration"] : ["exfiltration"],
        }));
      }
    }
  }
}
