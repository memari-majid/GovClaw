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
 * Shared utilities for the plugin scanner: comment stripping, path detection,
 * file collection, finding factory, deduplication, and assessment computation.
 */
import { readdir, stat, access } from "node:fs/promises";
import { join } from "node:path";
import type {
  Finding,
  Severity,
  ScanResult,
  ScanMetadata,
  Assessment,
  AssessmentCategory,
  CategoryStatus,
  ScanVerdict,
} from "../../types.js";
import { DEPRIORITIZED_PATH_PATTERNS, TAXONOMY_MAP } from "./rules.js";

// ---------------------------------------------------------------------------
// Scanner name
// ---------------------------------------------------------------------------

export const SCANNER_NAME = "defenseclaw-plugin-scanner";

// ---------------------------------------------------------------------------
// Evidence helpers
// ---------------------------------------------------------------------------

const MAX_EVIDENCE_LEN = 200;
const SECRET_REDACT_RE = /(?:AKIA|sk_live_|pk_live_|sk_test_|pk_test_|ghp_|gho_|ghu_|ghs_|ghr_|xox[bpors]-|AIza|eyJ)[A-Za-z0-9\-_+/=.]{6,}/g;

/** Truncate and optionally redact a source line for use as evidence. */
export function sanitiseEvidence(line: string, redact = false): string {
  let evidence = line.trim();
  if (redact) {
    evidence = evidence.replace(SECRET_REDACT_RE, (m) => m.slice(0, 6) + "***REDACTED***");
  }
  if (evidence.length > MAX_EVIDENCE_LEN) {
    evidence = evidence.slice(0, MAX_EVIDENCE_LEN) + "…";
  }
  return evidence;
}

// ---------------------------------------------------------------------------
// Comment / path helpers
// ---------------------------------------------------------------------------

/**
 * Strip single-line comments from a line to avoid false-positive pattern
 * matches on commented-out code. Preserves strings containing "//".
 */
export function stripComment(line: string): string {
  let inString: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const prev = i > 0 ? line[i - 1] : "";

    if (inString) {
      if (ch === inString && prev !== "\\") inString = null;
      continue;
    }

    if (ch === '"' || ch === "'" || ch === "`") {
      inString = ch;
      continue;
    }

    if (ch === "/" && i + 1 < line.length && line[i + 1] === "/") {
      return line.slice(0, i).trimEnd();
    }
  }
  return line;
}

/** Quick check if a raw line is a single-line comment. */
export function isCommentLine(line: string): boolean {
  return /^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*\/\*/.test(line);
}

export function isTestPath(relPath: string): boolean {
  return DEPRIORITIZED_PATH_PATTERNS.some((re) => re.test(relPath));
}

/** Downgrade severity by one level (for test-path findings). */
export function downgrade(severity: Severity): Severity {
  switch (severity) {
    case "CRITICAL": return "HIGH";
    case "HIGH": return "MEDIUM";
    case "MEDIUM": return "LOW";
    case "LOW": return "INFO";
    case "INFO": return "INFO";
  }
}

// ---------------------------------------------------------------------------
// File system helpers
// ---------------------------------------------------------------------------

export async function collectFiles(
  dir: string,
  extensions: string[],
  maxDepth = 4,
  depth = 0,
): Promise<string[]> {
  if (depth >= maxDepth) return [];

  const files: string[] = [];
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return files;
  }

  for (const entry of entries) {
    if (entry === "node_modules" || entry === "dist" || entry.startsWith("."))
      continue;

    const fullPath = join(dir, entry);
    try {
      const info = await stat(fullPath);
      if (info.isDirectory()) {
        const nested = await collectFiles(fullPath, extensions, maxDepth, depth + 1);
        files.push(...nested);
      } else if (extensions.some((ext) => entry.endsWith(ext))) {
        files.push(fullPath);
      }
    } catch {
      continue;
    }
  }

  return files;
}

export async function checkLockfilePresence(dir: string): Promise<boolean> {
  for (const name of ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]) {
    try {
      await access(join(dir, name));
      return true;
    } catch {
      continue;
    }
  }
  return false;
}

export async function dirExists(path: string): Promise<boolean> {
  try {
    const s = await stat(path);
    return s.isDirectory();
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Finding factory
// ---------------------------------------------------------------------------

export interface MakeFindingOpts {
  rule_id: string;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  evidence?: string;
  location?: string;
  remediation?: string;
  tags?: string[];
}

export function makeFinding(id: number, opts: MakeFindingOpts): Finding {
  return {
    id: `plugin-${id}`,
    rule_id: opts.rule_id,
    severity: opts.severity,
    confidence: opts.confidence,
    title: opts.title,
    description: opts.description,
    evidence: opts.evidence,
    location: opts.location,
    remediation: opts.remediation,
    scanner: SCANNER_NAME,
    tags: opts.tags,
    taxonomy: TAXONOMY_MAP[opts.rule_id],
  };
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

/**
 * Merge multiple hits on the same rule into one finding with
 * `occurrence_count`. Rules whose title contains a variable part (e.g.
 * "Dangerous permission: fs:*") use rule_id+title as key so different
 * permissions stay separate.
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  const out: Finding[] = [];

  for (const f of findings) {
    const key = `${f.rule_id ?? ""}::${f.title}`;
    const existing = seen.get(key);
    if (existing) {
      existing.occurrence_count = (existing.occurrence_count ?? 1) + 1;
      const rank: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
      if ((rank[f.severity] ?? 0) > (rank[existing.severity] ?? 0)) {
        existing.severity = f.severity;
        existing.confidence = f.confidence;
        existing.location = f.location;
        existing.evidence = f.evidence;
      }
    } else {
      const copy = { ...f, occurrence_count: 1 };
      seen.set(key, copy);
      out.push(copy);
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Assessment computation
// ---------------------------------------------------------------------------

const ASSESSMENT_CATEGORIES: ReadonlyArray<{ name: string; tags: string[]; ruleIds: string[] }> = [
  { name: "permissions", tags: [], ruleIds: ["PERM-DANGEROUS", "PERM-WILDCARD", "PERM-NONE", "TOOL-PERM-DANGEROUS"] },
  { name: "supply-chain", tags: ["supply-chain"], ruleIds: [] },
  { name: "credentials", tags: ["credential-theft"], ruleIds: [] },
  { name: "exfiltration", tags: ["exfiltration"], ruleIds: [] },
  { name: "code-execution", tags: ["code-execution"], ruleIds: ["SRC-EVAL", "SRC-NEW-FUNC", "SRC-CHILD-PROC", "SRC-EXEC", "SRC-DENO-RUN", "SRC-BUN-SPAWN"] },
  { name: "obfuscation", tags: ["obfuscation"], ruleIds: [] },
  { name: "gateway-integrity", tags: ["gateway-manipulation"], ruleIds: [] },
  { name: "cognitive-tampering", tags: ["cognitive-tampering"], ruleIds: [] },
];

function categoryStatus(findings: Finding[]): CategoryStatus {
  if (findings.length === 0) return "pass";
  const maxSev = findings.reduce(
    (max, f) => {
      const rank = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 }[f.severity] ?? 0;
      return rank > max ? rank : max;
    },
    0,
  );
  if (maxSev >= 4) return "fail";
  if (maxSev >= 3) return "warn";
  return "info";
}

export function computeAssessment(findings: Finding[]): Assessment {
  const categories: AssessmentCategory[] = ASSESSMENT_CATEGORIES.map((cat) => {
    const relevant = findings.filter(
      (f) =>
        cat.ruleIds.includes(f.rule_id ?? "") ||
        cat.tags.some((t) => f.tags?.includes(t)),
    );
    const status = categoryStatus(relevant);

    let summary: string;
    if (relevant.length === 0) {
      summary = "No issues detected.";
    } else {
      const counts = relevant.reduce(
        (acc, f) => { acc[f.severity] = (acc[f.severity] ?? 0) + 1; return acc; },
        {} as Record<string, number>,
      );
      const parts = Object.entries(counts)
        .sort(([a], [b]) => ({ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }[a] ?? 5) - ({ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }[b] ?? 5))
        .map(([sev, count]) => `${count} ${sev}`);
      summary = `${relevant.length} finding${relevant.length > 1 ? "s" : ""}: ${parts.join(", ")}.`;
    }

    return { name: cat.name, status, summary };
  });

  const hasCritical = findings.some((f) => f.severity === "CRITICAL");
  const hasHigh = findings.some((f) => f.severity === "HIGH");
  const hasMedium = findings.some((f) => f.severity === "MEDIUM");
  const maxConfidence = findings.length > 0
    ? Math.max(...findings.map((f) => f.confidence ?? 0))
    : 0;

  let verdict: ScanVerdict;
  let confidence: number;
  let summary: string;

  if (hasCritical) {
    verdict = "malicious";
    confidence = Math.min(maxConfidence, 0.95);
    summary = `Plugin has ${findings.filter((f) => f.severity === "CRITICAL").length} critical finding(s) indicating likely malicious behaviour.`;
  } else if (hasHigh) {
    verdict = "suspicious";
    confidence = Math.min(maxConfidence, 0.85);
    summary = `Plugin has ${findings.filter((f) => f.severity === "HIGH").length} high-severity finding(s) requiring review.`;
  } else if (hasMedium) {
    verdict = "suspicious";
    confidence = Math.min(maxConfidence, 0.6);
    summary = `Plugin has ${findings.filter((f) => f.severity === "MEDIUM").length} medium-severity finding(s). Review recommended.`;
  } else if (findings.length > 0) {
    verdict = "benign";
    confidence = 0.8;
    summary = "Plugin has only low/informational findings.";
  } else {
    verdict = "benign";
    confidence = 0.9;
    summary = "No security issues detected.";
  }

  return { verdict, confidence, summary, categories };
}

// ---------------------------------------------------------------------------
// Result builder
// ---------------------------------------------------------------------------

export function buildResult(
  target: string,
  findings: Finding[],
  startMs: number,
  metadata?: ScanMetadata,
): ScanResult {
  return {
    scanner: SCANNER_NAME,
    target,
    timestamp: new Date().toISOString(),
    findings,
    duration_ns: (Date.now() - startMs) * 1_000_000,
    metadata,
    assessment: computeAssessment(findings),
  };
}
