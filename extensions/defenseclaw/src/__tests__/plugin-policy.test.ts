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

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scanPlugin } from "../scanners/plugin_scanner/index.js";
import {
  defaultPolicy,
  fromPreset,
  disabledAnalyzerNames,
  applySeverityOverride,
  isSuppressed,
} from "../scanners/plugin_scanner/policy.js";

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "dc-policy-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe("policy presets", () => {
  it("default policy enables all analyzers", () => {
    const policy = defaultPolicy();
    expect(policy.policy_name).toBe("default");
    expect(policy.profile).toBe("default");
    expect(policy.analyzers.permissions).toBe(true);
    expect(policy.analyzers.source).toBe(true);
    expect(policy.analyzers.meta).toBe(true);
    expect(policy.disabled_rules.length).toBe(0);
    expect(policy.min_confidence).toBe(0.0);
  });

  it("strict policy upgrades severity for key rules", () => {
    const policy = fromPreset("strict");
    expect(policy.policy_name).toBe("strict");
    expect(policy.profile).toBe("strict");

    const evalOverride = policy.severity_overrides.find(
      (o) => o.rule_id === "SRC-EVAL",
    );
    expect(evalOverride).toBeDefined();
    expect(evalOverride!.severity).toBe("HIGH");

    const wildcardOverride = policy.severity_overrides.find(
      (o) => o.rule_id === "PERM-WILDCARD",
    );
    expect(wildcardOverride).toBeDefined();
    expect(wildcardOverride!.severity).toBe("HIGH");
  });

  it("strict policy has fewer safe dotfiles", () => {
    const def = defaultPolicy();
    const strict = fromPreset("strict");
    expect(strict.safe_dotfiles.length).toBeLessThan(def.safe_dotfiles.length);
  });

  it("permissive policy disables some analyzers", () => {
    const policy = fromPreset("permissive");
    expect(policy.policy_name).toBe("permissive");
    expect(policy.analyzers.bundleSize).toBe(false);
    expect(policy.analyzers.lockfile).toBe(false);
    expect(policy.analyzers.meta).toBe(false);
    expect(policy.analyzers.source).toBe(true); // source still enabled
  });

  it("permissive policy disables noise rules", () => {
    const policy = fromPreset("permissive");
    expect(policy.disabled_rules).toContain("PERM-NONE");
    expect(policy.disabled_rules).toContain("OBF-MINIFIED");
    expect(policy.disabled_rules).toContain("STRUCT-HIDDEN");
  });

  it("permissive policy sets min confidence", () => {
    const policy = fromPreset("permissive");
    expect(policy.min_confidence).toBe(0.5);
  });

  it("throws on unknown preset", () => {
    expect(() => fromPreset("nonexistent")).toThrow("Unknown policy preset");
  });
});

describe("disabledAnalyzerNames", () => {
  it("returns empty for default policy", () => {
    const disabled = disabledAnalyzerNames(defaultPolicy());
    expect(disabled.length).toBe(0);
  });

  it("maps policy keys to analyzer names for permissive", () => {
    const disabled = disabledAnalyzerNames(fromPreset("permissive"));
    expect(disabled).toContain("bundle-size");
    expect(disabled).toContain("lockfile");
    expect(disabled).toContain("meta");
    expect(disabled).not.toContain("source");
    expect(disabled).not.toContain("permissions");
  });
});

describe("severity overrides", () => {
  it("overrides finding severity", () => {
    const finding = { rule_id: "SRC-EVAL", severity: "MEDIUM" as const };
    applySeverityOverride(finding, [{ rule_id: "SRC-EVAL", severity: "CRITICAL" }]);
    expect(finding.severity).toBe("CRITICAL");
  });

  it("does not override unmatched rules", () => {
    const finding = { rule_id: "SRC-FETCH", severity: "INFO" as const };
    applySeverityOverride(finding, [{ rule_id: "SRC-EVAL", severity: "CRITICAL" }]);
    expect(finding.severity).toBe("INFO");
  });

  it("does nothing when no overrides", () => {
    const finding = { rule_id: "SRC-EVAL", severity: "MEDIUM" as const };
    applySeverityOverride(finding, []);
    expect(finding.severity).toBe("MEDIUM");
  });
});

describe("suppression", () => {
  it("suppresses disabled rules", () => {
    const policy = { ...defaultPolicy(), disabled_rules: ["PERM-NONE"] };
    expect(isSuppressed({ rule_id: "PERM-NONE" }, policy)).toBe(true);
    expect(isSuppressed({ rule_id: "PERM-DANGEROUS" }, policy)).toBe(false);
  });

  it("suppresses findings below min confidence", () => {
    const policy = { ...defaultPolicy(), min_confidence: 0.5 };
    expect(isSuppressed({ confidence: 0.3 }, policy)).toBe(true);
    expect(isSuppressed({ confidence: 0.7 }, policy)).toBe(false);
    expect(isSuppressed({ confidence: 0.5 }, policy)).toBe(false);
  });

  it("suppresses when both rule and confidence match", () => {
    const policy = {
      ...defaultPolicy(),
      disabled_rules: ["PERM-NONE"],
      min_confidence: 0.5,
    };
    expect(isSuppressed({ rule_id: "PERM-NONE", confidence: 0.3 }, policy)).toBe(true);
  });
});

describe("policy integration with scanPlugin", () => {
  it("strict policy reports eval as HIGH (upgraded from MEDIUM)", async () => {
    await writeFile(
      join(tempDir, "package.json"),
      JSON.stringify({ name: "eval-strict", permissions: ["fs:read"] }),
    );
    await writeFile(
      join(tempDir, "index.ts"),
      'const result = eval("1+1");\n',
    );

    const result = await scanPlugin(tempDir, { policy: "strict" });
    const evalFindings = result.findings.filter(
      (f) => f.rule_id === "SRC-EVAL",
    );

    expect(evalFindings.length).toBeGreaterThanOrEqual(1);
    expect(evalFindings[0].severity).toBe("HIGH"); // upgraded from MEDIUM
  });

  it("permissive policy suppresses PERM-NONE finding", async () => {
    await writeFile(
      join(tempDir, "package.json"),
      JSON.stringify({ name: "no-perms", version: "1.0.0" }),
    );

    const defaultResult = await scanPlugin(tempDir);
    const permissiveResult = await scanPlugin(tempDir, { policy: "permissive" });

    const defaultNoPerms = defaultResult.findings.filter(
      (f) => f.rule_id === "PERM-NONE",
    );
    const permissiveNoPerms = permissiveResult.findings.filter(
      (f) => f.rule_id === "PERM-NONE",
    );

    expect(defaultNoPerms.length).toBe(1); // default includes it
    expect(permissiveNoPerms.length).toBe(0); // permissive suppresses it
  });

  it("permissive policy suppresses hidden file findings", async () => {
    await writeFile(
      join(tempDir, "package.json"),
      JSON.stringify({ name: "hidden", permissions: ["fs:read"] }),
    );
    await writeFile(join(tempDir, ".backdoor"), "data");

    const defaultResult = await scanPlugin(tempDir);
    const permissiveResult = await scanPlugin(tempDir, { policy: "permissive" });

    const defaultHidden = defaultResult.findings.filter(
      (f) => f.rule_id === "STRUCT-HIDDEN",
    );
    const permissiveHidden = permissiveResult.findings.filter(
      (f) => f.rule_id === "STRUCT-HIDDEN",
    );

    expect(defaultHidden.length).toBe(1);
    expect(permissiveHidden.length).toBe(0);
  });

  it("permissive policy skips bundle-size analyzer", async () => {
    await writeFile(
      join(tempDir, "package.json"),
      JSON.stringify({ name: "big-bundle", permissions: ["fs:read"] }),
    );
    await mkdir(join(tempDir, "dist"), { recursive: true });
    // Create a file over threshold
    await writeFile(join(tempDir, "dist", "bundle.js"), "x".repeat(600 * 1024));

    const defaultResult = await scanPlugin(tempDir);
    const permissiveResult = await scanPlugin(tempDir, { policy: "permissive" });

    const defaultBundle = defaultResult.findings.filter(
      (f) => f.rule_id === "STRUCT-LARGE-BUNDLE",
    );
    const permissiveBundle = permissiveResult.findings.filter(
      (f) => f.rule_id === "STRUCT-LARGE-BUNDLE",
    );

    expect(defaultBundle.length).toBe(1);
    expect(permissiveBundle.length).toBe(0); // analyzer disabled
  });

  it("same plugin, different policies, different finding counts", async () => {
    await writeFile(
      join(tempDir, "package.json"),
      JSON.stringify({
        name: "policy-comparison",
        version: "1.0.0",
        // no permissions → PERM-NONE finding
      }),
    );
    await writeFile(join(tempDir, ".custom-config"), "data"); // hidden file

    const defaultResult = await scanPlugin(tempDir);
    const permissiveResult = await scanPlugin(tempDir, { policy: "permissive" });

    // Permissive suppresses PERM-NONE and STRUCT-HIDDEN
    expect(permissiveResult.findings.length).toBeLessThan(defaultResult.findings.length);
  });
});
