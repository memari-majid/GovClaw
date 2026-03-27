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
 * Plugin scanner rule definitions, constants, and Cisco AITech taxonomy map.
 *
 * All pattern sets, severity defaults, and taxonomy references live here
 * so security reviewers can audit them without reading scan logic.
 */
import type { Severity, TaxonomyRef } from "../../types.js";

// ---------------------------------------------------------------------------
// Scan profile type
// ---------------------------------------------------------------------------

export type RuleProfile = "default" | "strict";

// ---------------------------------------------------------------------------
// Permission rules
// ---------------------------------------------------------------------------

export const DANGEROUS_PERMISSIONS = new Set([
  "fs:write",
  "fs:*",
  "net:*",
  "shell:exec",
  "shell:*",
  "system:*",
  "crypto:*",
]);
// env:read removed — reading environment variables is normal plugin behaviour.
// env:* remains dangerous because it grants env write.

// ---------------------------------------------------------------------------
// Dependency rules
// ---------------------------------------------------------------------------

export const RISKY_DEPENDENCIES = new Set([
  "child_process",
  "shelljs",
  "execa",
  "node-pty",
  "vm2",
  "isolated-vm",
  "node-serialize",
  // serialize-javascript removed — it is webpack's SAFE serialiser.
  "decompress",
  "adm-zip",
  "cross-spawn",
  // minimist removed — widely-used argument parser, not inherently risky.
]);

// ---------------------------------------------------------------------------
// Install script rules
// ---------------------------------------------------------------------------

export const DANGEROUS_INSTALL_SCRIPTS = new Set(["preinstall", "postinstall", "install"]);

export const SHELL_COMMANDS_IN_SCRIPTS =
  /\b(?:curl|wget|bash|sh|powershell|nc|ncat|netcat|chmod|sudo|rm\s+-rf|dd\s+if=)\b/i;

// ---------------------------------------------------------------------------
// Exfiltration domains (C2)
// ---------------------------------------------------------------------------

export const C2_DOMAINS = new Set([
  "webhook.site",
  "ngrok.io",
  "ngrok-free.app",
  "pipedream.net",
  "requestbin.com",
  "hookbin.com",
  "burpcollaborator.net",
  "interact.sh",
  "oast.fun",
  "canarytokens.com",
]);

// ---------------------------------------------------------------------------
// Cognitive files (agent identity / behaviour)
// ---------------------------------------------------------------------------

export const COGNITIVE_FILES = new Set([
  "SOUL.md",
  "IDENTITY.md",
  "TOOLS.md",
  "AGENTS.md",
  "MEMORY.md",
  "openclaw.json",
  "gateway.json",
  "config.yaml",
]);

// ---------------------------------------------------------------------------
// Structural rules
// ---------------------------------------------------------------------------

export const BINARY_EXTENSIONS = new Set([".exe", ".so", ".dylib", ".wasm", ".dll"]);
export const SCRIPT_EXTENSIONS = new Set([".sh", ".bat", ".cmd"]);

export const SAFE_DOTFILES = new Set([
  ".gitignore", ".eslintrc", ".eslintrc.js", ".eslintrc.json", ".eslintrc.cjs",
  ".prettierrc", ".prettierrc.json", ".prettierignore",
  ".npmrc", ".npmignore", ".editorconfig", ".nvmrc",
  ".tsconfig.json",
]);

// ---------------------------------------------------------------------------
// Path de-prioritisation (test / fixture / build output)
// ---------------------------------------------------------------------------

export const DEPRIORITIZED_PATH_PATTERNS = [
  /\/__tests__\//,
  /\/test\//,
  /\/tests\//,
  /\/fixtures?\//,
  /\/dist\//,
  /\/build\//,
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
];

// ---------------------------------------------------------------------------
// Source-level pattern rules
// ---------------------------------------------------------------------------

export interface SourcePatternRule {
  id: string;
  pattern: RegExp;
  title: string;
  severity: Severity;
  confidence: number;
  profiles: RuleProfile[];
  tags: string[];
  capability?: string;
}

export const SOURCE_PATTERN_RULES: SourcePatternRule[] = [
  // --- code-execution: always reported ---
  { id: "SRC-EVAL", pattern: /\beval\s*\(/, title: "Uses eval()", severity: "MEDIUM", confidence: 0.85, profiles: ["default", "strict"], tags: ["code-execution"], capability: "eval" },
  { id: "SRC-NEW-FUNC", pattern: /\bnew\s+Function\s*\(/, title: "Uses dynamic Function constructor", severity: "MEDIUM", confidence: 0.85, profiles: ["default", "strict"], tags: ["code-execution"], capability: "eval" },
  { id: "SRC-CHILD-PROC", pattern: /\bchild_process\b/, title: "Imports child_process", severity: "INFO", confidence: 0.7, profiles: ["default", "strict"], tags: ["code-execution"], capability: "child-process" },
  { id: "SRC-EXEC", pattern: /\bexec\s*\(/, title: "Calls exec()", severity: "INFO", confidence: 0.5, profiles: ["strict"], tags: ["code-execution"], capability: "child-process" },
  { id: "SRC-DENO-RUN", pattern: /\bDeno\.run\b/, title: "Uses Deno.run", severity: "MEDIUM", confidence: 0.85, profiles: ["default", "strict"], tags: ["code-execution"], capability: "child-process" },
  { id: "SRC-BUN-SPAWN", pattern: /\bBun\.spawn\b/, title: "Uses Bun.spawn", severity: "MEDIUM", confidence: 0.85, profiles: ["default", "strict"], tags: ["code-execution"], capability: "child-process" },

  // --- network: default profile suppresses low-signal ---
  { id: "SRC-FETCH", pattern: /\b(?:fetch|https?\.request|undici\.request)\s*\(/, title: "Makes network requests", severity: "INFO", confidence: 0.3, profiles: ["strict"], tags: ["network-access"], capability: "network" },
  { id: "SRC-NET-SERVER", pattern: /\bnet\.createServer\b/, title: "Creates a network server", severity: "MEDIUM", confidence: 0.8, profiles: ["default", "strict"], tags: ["network-access"], capability: "network" },
  { id: "SRC-HTTP-SERVER", pattern: /\bhttp\.createServer\b/, title: "Creates an HTTP server", severity: "MEDIUM", confidence: 0.8, profiles: ["default", "strict"], tags: ["network-access"], capability: "network" },
  { id: "SRC-WS", pattern: /\bnew\s+WebSocket\b/, title: "Uses WebSocket connections", severity: "INFO", confidence: 0.5, profiles: ["strict"], tags: ["network-access"], capability: "network" },

  // --- env access ---
  { id: "SRC-ENV-READ", pattern: /\bprocess\.env\b/, title: "Reads environment variables", severity: "INFO", confidence: 0.3, profiles: ["strict"], tags: ["env-access"], capability: "env-access" },

  // --- filesystem ---
  { id: "SRC-FS-WRITE", pattern: /\bfs\.write/, title: "Performs filesystem writes", severity: "INFO", confidence: 0.6, profiles: ["default", "strict"], tags: ["filesystem"], capability: "filesystem-write" },
];

// ---------------------------------------------------------------------------
// Secret patterns
// ---------------------------------------------------------------------------

export const SECRET_PATTERNS: Array<{ id: string; pattern: RegExp; title: string; confidence: number }> = [
  { id: "SEC-AWS", pattern: /(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}/, title: "Possible AWS access key", confidence: 0.95 },
  { id: "SEC-STRIPE", pattern: /(?:sk_live_|pk_live_|sk_test_|pk_test_)[a-zA-Z0-9]{20,}/, title: "Possible Stripe key", confidence: 0.95 },
  { id: "SEC-GITHUB", pattern: /(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}/, title: "Possible GitHub token", confidence: 0.95 },
  { id: "SEC-PRIVKEY", pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/, title: "Private key embedded in source", confidence: 0.98 },
  { id: "SEC-GOOGLE", pattern: /AIza[0-9A-Za-z\-_]{35}/, title: "Possible Google API key", confidence: 0.9 },
  { id: "SEC-SLACK", pattern: /xox[bpors]-[0-9a-zA-Z\-]{10,}/, title: "Possible Slack token", confidence: 0.9 },
  { id: "SEC-JWT", pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*/, title: "Possible JWT token", confidence: 0.7 },
  { id: "SEC-CONNSTR", pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@/, title: "Connection string with embedded credentials", confidence: 0.9 },
];

// ---------------------------------------------------------------------------
// Credential path patterns
// ---------------------------------------------------------------------------

export const CREDENTIAL_PATH_PATTERNS: Array<{ id: string; pattern: RegExp; title: string }> = [
  { id: "CRED-OPENCLAW-DIR", pattern: /\.openclaw\/credentials/i, title: "Accesses OpenClaw credentials directory" },
  { id: "CRED-OPENCLAW-ENV", pattern: /\.openclaw\/\.env/i, title: "Accesses OpenClaw .env file" },
  { id: "CRED-OPENCLAW-AGENTS", pattern: /\.openclaw\/agents\//i, title: "Accesses OpenClaw agents directory" },
  { id: "CRED-READFILE-SECRETS", pattern: /readFile\w*\s*\([^)]*(?:\.env|credentials|secrets)/i, title: "Reads credential or secrets files" },
];

// ---------------------------------------------------------------------------
// Gateway manipulation patterns
// ---------------------------------------------------------------------------

export const GATEWAY_PATTERNS: Array<{ id: string; pattern: RegExp; title: string; severity: Severity; confidence: number }> = [
  { id: "GW-PROCESS-EXIT", pattern: /\bprocess\.exit\s*\(/, title: "Calls process.exit()", severity: "HIGH", confidence: 0.9 },
  { id: "GW-MODULE-IMPORT", pattern: /\b(?:require|import)\s*\(\s*['"]module['"]\s*\)/, title: "Imports Node module system", severity: "HIGH", confidence: 0.9 },
  { id: "GW-MODULE-LOAD", pattern: /\bModule\._load\b/, title: "Manipulates Module._load", severity: "HIGH", confidence: 0.95 },
  { id: "GW-GLOBAL-MOD", pattern: /\bglobalThis\s*[.[=]|\bglobal\s*\.\s*\w+\s*=/, title: "Modifies global state", severity: "MEDIUM", confidence: 0.7 },
  { id: "GW-PROTO-DEFINE", pattern: /Object\.defineProperty\s*\(\s*Object\.prototype/, title: "Prototype pollution via Object.defineProperty", severity: "CRITICAL", confidence: 0.98 },
  { id: "GW-PROTO-ACCESS", pattern: /__proto__\s*[=\[]/, title: "Accesses __proto__ (prototype pollution risk)", severity: "HIGH", confidence: 0.85 },
  { id: "GW-ENV-WRITE", pattern: /\bprocess\.env\s*\.\s*\w+\s*=/, title: "Modifies environment variables at runtime", severity: "MEDIUM", confidence: 0.8 },
];

// ---------------------------------------------------------------------------
// Write-function detection (cognitive tampering)
// ---------------------------------------------------------------------------

export const WRITE_FUNCTIONS = /(?:writeFile|appendFile|writeFileSync|appendFileSync|createWriteStream)\s*\(/;

// ---------------------------------------------------------------------------
// SSRF / Cloud metadata patterns
// ---------------------------------------------------------------------------

export const CLOUD_METADATA_PATTERNS: Array<{ id: string; pattern: RegExp; title: string; confidence: number }> = [
  { id: "SSRF-AWS-META", pattern: /169\.254\.169\.254/, title: "AWS EC2 metadata endpoint reference", confidence: 0.95 },
  { id: "SSRF-GCP-META", pattern: /metadata\.google\.internal/, title: "GCP metadata endpoint reference", confidence: 0.95 },
  { id: "SSRF-AZURE-META", pattern: /169\.254\.169\.254.*metadata\/instance|metadata\/instance.*169\.254\.169\.254/, title: "Azure metadata endpoint reference", confidence: 0.9 },
  { id: "SSRF-ALIBABA-META", pattern: /100\.100\.100\.200/, title: "Alibaba Cloud metadata endpoint reference", confidence: 0.9 },
  { id: "SSRF-LINK-LOCAL", pattern: /169\.254\.\d{1,3}\.\d{1,3}/, title: "Link-local IP address reference", confidence: 0.7 },
];

export const PRIVATE_IP_PATTERN = /(?:^|\b)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\b|$)/;

export const INTERNAL_HOSTNAME_PATTERNS = /\b(?:localhost|internal|corp|local|intranet|private)\b.*\b(?:fetch|http|request|get|post)\b|\b(?:fetch|http|request|get|post)\b.*\b(?:localhost|internal|corp|local|intranet|private)\b/i;

// ---------------------------------------------------------------------------
// Dynamic import / require patterns
// ---------------------------------------------------------------------------

export const DYNAMIC_IMPORT_PATTERNS: Array<{ id: string; pattern: RegExp; title: string; severity: Severity; confidence: number }> = [
  { id: "DYN-IMPORT", pattern: /\bimport\s*\(\s*(?!['"][^'"]+['"]\s*\))/, title: "Dynamic import() with non-literal argument", severity: "MEDIUM", confidence: 0.8 },
  { id: "DYN-REQUIRE", pattern: /\brequire\s*\(\s*(?!['"][^'"]+['"]\s*\))/, title: "Dynamic require() with non-literal argument", severity: "MEDIUM", confidence: 0.75 },
  { id: "DYN-SPAWN-VAR", pattern: /\b(?:spawn|execFile|fork)\s*\(\s*(?!['"][^'"]+['"]\s*[,)])/, title: "Process spawn with non-literal command", severity: "HIGH", confidence: 0.85 },
];

// ---------------------------------------------------------------------------
// Bundle size threshold
// ---------------------------------------------------------------------------

export const BUNDLE_SIZE_THRESHOLD_BYTES = 500 * 1024; // 500 KB
export const BUNDLE_DIRS = new Set(["dist", "build", "out", "bundle"]);

// ---------------------------------------------------------------------------
// JSON config scanning patterns
// ---------------------------------------------------------------------------

export const JSON_SECRET_PATTERNS: Array<{ id: string; pattern: RegExp; title: string; confidence: number }> = [
  { id: "JSON-SEC-AWS", pattern: /(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}/, title: "AWS key in config file", confidence: 0.95 },
  { id: "JSON-SEC-PRIVKEY", pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/, title: "Private key in config file", confidence: 0.98 },
  { id: "JSON-SEC-CONNSTR", pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@/, title: "Connection string in config file", confidence: 0.9 },
  { id: "JSON-SEC-GENERIC", pattern: /["'](?:password|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']\s*:\s*["'][^"']{8,}["']/i, title: "Possible secret in config key-value pair", confidence: 0.7 },
];

export const JSON_URL_PATTERNS: Array<{ id: string; pattern: RegExp; title: string; confidence: number }> = [
  { id: "JSON-URL-HTTP", pattern: /["']https?:\/\/(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|localhost|127\.0\.0\.1)/, title: "Metadata/localhost URL in config", confidence: 0.9 },
  { id: "JSON-URL-C2", pattern: /["']https?:\/\/[^"']*(?:webhook\.site|ngrok\.io|pipedream\.net|requestbin\.com|interact\.sh|oast\.fun|burpcollaborator\.net)/, title: "Known C2 domain in config", confidence: 0.95 },
];

// ---------------------------------------------------------------------------
// Cisco AITech Taxonomy mapping — rule_id → taxonomy reference
// See: src/scanners/taxonomy.json (Cisco AI Security Taxonomy v1.0.0)
// ---------------------------------------------------------------------------

export const TAXONOMY_MAP: Record<string, TaxonomyRef> = {
  // OB-009: Supply Chain Compromise
  "SCRIPT-INSTALL-HOOK":  { objective: "OB-009", technique: "AITech-9.3", sub_technique: "AISubtech-9.3.1" },
  "SCRIPT-SHELL-CMD":     { objective: "OB-009", technique: "AITech-9.3", sub_technique: "AISubtech-9.3.1" },
  "DEP-RISKY":            { objective: "OB-009", technique: "AITech-9.3", sub_technique: "AISubtech-9.3.1" },
  "DEP-UNPINNED":         { objective: "OB-009", technique: "AITech-9.3", sub_technique: "AISubtech-9.3.3" },
  "DEP-HTTP":             { objective: "OB-009", technique: "AITech-9.3", sub_technique: "AISubtech-9.3.3" },
  "DEP-LOCAL-FILE":       { objective: "OB-009", technique: "AITech-9.3", sub_technique: "AISubtech-9.3.1" },
  "DEP-GIT-UNPIN":        { objective: "OB-009", technique: "AITech-9.3", sub_technique: "AISubtech-9.3.3" },
  "STRUCT-NO-LOCKFILE":   { objective: "OB-009", technique: "AITech-9.3", sub_technique: "AISubtech-9.3.3" },
  "MANIFEST-MISSING":     { objective: "OB-009", technique: "AITech-9.3" },
  "STRUCT-BINARY":        { objective: "OB-009", technique: "AITech-9.2", sub_technique: "AISubtech-9.2.2" },
  "STRUCT-SCRIPT":        { objective: "OB-009", technique: "AITech-9.3", sub_technique: "AISubtech-9.3.1" },

  // OB-009 / Detection Evasion
  "OBF-BASE64":           { objective: "OB-009", technique: "AITech-9.2", sub_technique: "AISubtech-9.2.1" },
  "OBF-CHARCODE":         { objective: "OB-009", technique: "AITech-9.2", sub_technique: "AISubtech-9.2.1" },
  "OBF-HEX":              { objective: "OB-009", technique: "AITech-9.2", sub_technique: "AISubtech-9.2.1" },
  "OBF-CONCAT":           { objective: "OB-009", technique: "AITech-9.2", sub_technique: "AISubtech-9.2.1" },
  "OBF-MINIFIED":         { objective: "OB-009", technique: "AITech-9.2", sub_technique: "AISubtech-9.2.1" },

  // OB-014: Privilege Compromise
  "PERM-DANGEROUS":       { objective: "OB-014", technique: "AITech-14.2", sub_technique: "AISubtech-14.2.1" },
  "PERM-WILDCARD":        { objective: "OB-014", technique: "AITech-14.2", sub_technique: "AISubtech-14.2.1" },
  "PERM-NONE":            { objective: "OB-014", technique: "AITech-14.1", sub_technique: "AISubtech-14.1.2" },
  "TOOL-NO-DESC":         { objective: "OB-014", technique: "AITech-14.1", sub_technique: "AISubtech-14.1.2" },
  "TOOL-PERM-DANGEROUS":  { objective: "OB-014", technique: "AITech-14.2", sub_technique: "AISubtech-14.2.1" },

  // OB-008: Data Privacy / Credential Theft
  "SEC-AWS":              { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "SEC-STRIPE":           { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "SEC-GITHUB":           { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "SEC-PRIVKEY":          { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "SEC-GOOGLE":           { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "SEC-SLACK":            { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "SEC-JWT":              { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "SEC-CONNSTR":          { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "CRED-OPENCLAW-DIR":    { objective: "OB-014", technique: "AITech-14.1", sub_technique: "AISubtech-14.1.1" },
  "CRED-OPENCLAW-ENV":    { objective: "OB-014", technique: "AITech-14.1", sub_technique: "AISubtech-14.1.1" },
  "CRED-OPENCLAW-AGENTS": { objective: "OB-014", technique: "AITech-14.1", sub_technique: "AISubtech-14.1.1" },
  "CRED-READFILE-SECRETS":{ objective: "OB-014", technique: "AITech-14.1", sub_technique: "AISubtech-14.1.1" },
  "STRUCT-ENV-FILE":      { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },

  // OB-008: Exfiltration
  "EXFIL-C2-DOMAIN":      { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "EXFIL-DNS":            { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },

  // OB-012: Action-Space Abuse / Code Execution
  "SRC-EVAL":             { objective: "OB-012", technique: "AITech-12.1", sub_technique: "AISubtech-12.1.3" },
  "SRC-NEW-FUNC":         { objective: "OB-012", technique: "AITech-12.1", sub_technique: "AISubtech-12.1.3" },
  "SRC-CHILD-PROC":       { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.1" },
  "SRC-EXEC":             { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.1" },
  "SRC-DENO-RUN":         { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.1" },
  "SRC-BUN-SPAWN":        { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.1" },
  "SRC-FETCH":            { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "SRC-NET-SERVER":       { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "SRC-HTTP-SERVER":      { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "SRC-WS":               { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "SRC-ENV-READ":         { objective: "OB-008", technique: "AITech-8.3", sub_technique: "AISubtech-8.3.2" },
  "SRC-FS-WRITE":         { objective: "OB-012", technique: "AITech-12.1", sub_technique: "AISubtech-12.1.3" },

  // OB-005: Persistence / Cognitive Tampering
  "COG-TAMPER":           { objective: "OB-005", technique: "AITech-5.2", sub_technique: "AISubtech-5.2.1" },

  // OB-012 / OB-013: Gateway Manipulation
  "GW-PROCESS-EXIT":      { objective: "OB-013", technique: "AITech-13.1", sub_technique: "AISubtech-13.1.4" },
  "GW-MODULE-IMPORT":     { objective: "OB-012", technique: "AITech-12.1", sub_technique: "AISubtech-12.1.3" },
  "GW-MODULE-LOAD":       { objective: "OB-012", technique: "AITech-12.1", sub_technique: "AISubtech-12.1.3" },
  "GW-GLOBAL-MOD":        { objective: "OB-012", technique: "AITech-12.1", sub_technique: "AISubtech-12.1.2" },
  "GW-PROTO-DEFINE":      { objective: "OB-012", technique: "AITech-12.1", sub_technique: "AISubtech-12.1.2" },
  "GW-PROTO-ACCESS":      { objective: "OB-012", technique: "AITech-12.1", sub_technique: "AISubtech-12.1.2" },
  "GW-ENV-WRITE":         { objective: "OB-012", technique: "AITech-12.1", sub_technique: "AISubtech-12.1.3" },

  // OB-013: Availability / Cost Abuse
  "COST-RUNAWAY":         { objective: "OB-013", technique: "AITech-13.2", sub_technique: "AISubtech-13.2.1" },

  // Structural
  "STRUCT-HIDDEN":        { objective: "OB-009", technique: "AITech-9.2", sub_technique: "AISubtech-9.2.2" },

  // SSRF / Cloud metadata — OB-009: Unauthorized Network Access
  "SSRF-AWS-META":        { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "SSRF-GCP-META":        { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "SSRF-AZURE-META":      { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "SSRF-ALIBABA-META":    { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "SSRF-LINK-LOCAL":      { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "SSRF-PRIVATE-IP":      { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "SSRF-INTERNAL-HOST":   { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },

  // OpenClaw plugin manifest — OB-014: Insufficient Access Controls
  "CLAW-MANIFEST-MISSING":{ objective: "OB-014", technique: "AITech-14.1", sub_technique: "AISubtech-14.1.2" },
  "CLAW-HOOK-DANGEROUS":  { objective: "OB-012", technique: "AITech-12.1", sub_technique: "AISubtech-12.1.2" },
  "CLAW-TOOL-NO-DESC":    { objective: "OB-014", technique: "AITech-14.1", sub_technique: "AISubtech-14.1.2" },

  // Bundle size — OB-009: Obfuscation (can't audit large bundles)
  "STRUCT-LARGE-BUNDLE":  { objective: "OB-009", technique: "AITech-9.2", sub_technique: "AISubtech-9.2.1" },

  // Dynamic imports — OB-009: Code Execution
  "DYN-IMPORT":           { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.1" },
  "DYN-REQUIRE":          { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.1" },
  "DYN-SPAWN-VAR":        { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.1" },

  // JSON config secrets — OB-008: Data Exfiltration via Agent Tooling
  "JSON-SEC-AWS":         { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "JSON-SEC-PRIVKEY":     { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "JSON-SEC-CONNSTR":     { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "JSON-SEC-GENERIC":     { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "JSON-URL-HTTP":        { objective: "OB-009", technique: "AITech-9.1", sub_technique: "AISubtech-9.1.3" },
  "JSON-URL-C2":          { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },

  // Meta-analyzer cross-reference rules
  "META-EXFIL-CHAIN":        { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
  "META-EVASIVE-ATTACK":     { objective: "OB-009", technique: "AITech-9.2", sub_technique: "AISubtech-9.2.1" },
  "META-SUPPLY-CHAIN":       { objective: "OB-009", technique: "AITech-9.3", sub_technique: "AISubtech-9.3.1" },
  "META-PERSISTENT-COMPROMISE": { objective: "OB-005", technique: "AITech-5.2", sub_technique: "AISubtech-5.2.1" },
  "META-CLOUD-CRED-THEFT":   { objective: "OB-008", technique: "AITech-8.2", sub_technique: "AISubtech-8.2.3" },
};
