/**
 * DefenseClaw Plugin Scanner — orchestrator.
 *
 * This is the public entry point. It loads the manifest, runs each analysis
 * phase, deduplicates findings, and computes the assessment.
 *
 * Rule definitions:    ./plugin-rules.ts
 * Analysis phases:     ./plugin-analyzers.ts
 * Helpers & utilities: ./plugin-helpers.ts
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
import {
  makeFinding,
  deduplicateFindings,
  buildResult,
  checkLockfilePresence,
  dirExists,
} from "./helpers.js";
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

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function scanPlugin(
  pluginDir: string,
  options?: PluginScanOptions,
): Promise<ScanResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  const target = resolve(pluginDir);
  const capabilities = new Set<string>();
  const profile: ScanProfile = options?.profile ?? "default";

  // --- Load manifest ---
  const manifest = await loadManifest(target);
  if (!manifest) {
    findings.push(makeFinding(findings.length + 1, {
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
    }));
    return buildResult(target, findings, start);
  }

  // --- Manifest checks ---
  checkPermissions(manifest, findings, target);
  checkDependencies(manifest, findings, target);
  checkInstallScripts(manifest, findings, target);

  if (manifest.tools) {
    for (const tool of manifest.tools) {
      checkTool(tool, findings, target);
    }
  }

  // --- Source analysis ---
  const { fileCount, totalBytes } = await scanSourceFiles(
    target, findings, capabilities, profile,
  );

  // --- Directory structure ---
  await scanDirectoryStructure(target, findings);

  // --- OpenClaw native manifest ---
  await scanClawManifest(target, findings);

  // --- Bundle size ---
  await scanBundleSize(target, findings);

  // --- JSON config artifacts ---
  await scanJsonConfigs(target, findings);

  // --- Lockfile check ---
  const hasLockfile = await checkLockfilePresence(target);
  if (!hasLockfile && manifest.dependencies && Object.keys(manifest.dependencies).length > 0) {
    // Published packages don't ship lockfiles (npm strips them during pack).
    // Only flag this for dev workspaces that have node_modules/.
    const isDistributed = !(await dirExists(join(target, "node_modules")));
    if (!isDistributed) {
      findings.push(makeFinding(findings.length + 1, {
        rule_id: "STRUCT-NO-LOCKFILE",
        severity: "MEDIUM",
        confidence: 1.0,
        title: "No lockfile found",
        description:
          "Plugin has dependencies but no package-lock.json, yarn.lock, or pnpm-lock.yaml. " +
          "Without a lockfile, builds are non-deterministic and vulnerable to dependency confusion.",
        location: target,
        remediation: "Run npm install to generate a package-lock.json and commit it.",
        tags: ["supply-chain"],
      }));
    }
  }

  // --- Build result ---
  const metadata: ScanMetadata = {
    manifest_name: manifest.name,
    manifest_version: manifest.version,
    file_count: fileCount,
    total_size_bytes: totalBytes,
    has_lockfile: hasLockfile,
    has_install_scripts: hasInstallScripts(manifest),
    detected_capabilities: [...capabilities].sort(),
  };

  return buildResult(target, deduplicateFindings(findings), start, metadata);
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
