import { readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import yaml from "js-yaml";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_API_PORT = 18790;

interface SidecarConfig {
  host: string;
  apiPort: number;
  baseUrl: string;
}

let cached: SidecarConfig | undefined;

/**
 * Read gateway.host and gateway.api_port from ~/.defenseclaw/config.yaml.
 * Falls back to defaults (127.0.0.1:18790) if the file is missing or
 * malformed. Result is cached for the lifetime of the process.
 */
export function loadSidecarConfig(): SidecarConfig {
  if (cached) return cached;

  let host = DEFAULT_HOST;
  let apiPort = DEFAULT_API_PORT;

  try {
    const cfgPath = join(homedir(), ".defenseclaw", "config.yaml");
    const raw = yaml.load(readFileSync(cfgPath, "utf8")) as Record<string, unknown> | null;
    if (raw && typeof raw === "object") {
      const gw = raw["gateway"] as Record<string, unknown> | undefined;
      if (gw && typeof gw === "object") {
        if (typeof gw["host"] === "string" && gw["host"]) host = gw["host"];
        if (typeof gw["api_port"] === "number") apiPort = gw["api_port"];
      }
    }
  } catch {
    // Config missing or unreadable — use defaults
  }

  cached = { host, apiPort, baseUrl: `http://${host}:${apiPort}` };
  return cached;
}

/** Clear cached config (for testing). */
export function _resetSidecarConfigCache(): void {
  cached = undefined;
}
