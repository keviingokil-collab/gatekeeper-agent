/**
 * Configuration — environment variables only. No secret is ever hard-coded.
 *
 * Required:
 *   AGENT_GAMES_HMAC_SECRET — the platform-generated secret from the
 *     dashboard "Rotate Secret". The server refuses to start without it,
 *     and never falls back to a placeholder.
 *
 * Optional:
 *   PORT                     — default 3000
 *   GATEKEEPER_VK_HASH       — default: the registered mainnet vkHash
 *   CIRCUIT_WASM_PATH        — default: circuits/gatekeeper.wasm
 *   CIRCUIT_ZKEY_PATH        — default: circuits/gatekeeper_final.zkey
 *   VERIFICATION_KEY_PATH    — default: circuits/verification_key.json
 *   KURIER_ENABLED           — default "false" (local dev); set "true" in prod
 *   KURIER_API_KEY           — required when KURIER_ENABLED=true
 *   KURIER_API_URL           — default https://api.kurier.xyz/api/v1 (mainnet)
 *   KURIER_POLL_INTERVAL_MS  — default 5000
 *   KURIER_POLL_TIMEOUT_MS   — default 30000 (must fit inside REQUEST_TIMEOUT_MS)
 *   REQUEST_TIMEOUT_MS       — default 60000 (the platform's hard deadline)
 *   SEEN_STORE_PATH          — default ./data/seen.json
 *   TIMESTAMP_SKEW_MS        — default 300000 (5 min) for issued_at in future
 */

import { readFileSync } from "node:fs";

export const REGISTERED_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export const PROTOCOL_VERSION = "v1";

export interface AgentConfig {
  port: number;
  hmacSecret: string;
  vkHash: string;
  wasmPath: string;
  zkeyPath: string;
  verificationKeyPath: string;
  kurierEnabled: boolean;
  kurierApiKey: string;
  kurierApiUrl: string;
  kurierPollIntervalMs: number;
  kurierPollTimeoutMs: number;
  requestTimeoutMs: number;
  seenStorePath: string;
  timestampSkewMs: number;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`Invalid ${name}: ${JSON.stringify(raw)} (expected a non-negative integer)`);
  }
  return n;
}

function envBool(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  return raw.trim().toLowerCase() === "true";
}

/** Placeholder values that must never be accepted as the HMAC secret. */
const FORBIDDEN_SECRETS = new Set([
  "placeholder",
  "changeme",
  "test",
  "secret",
  "your-secret-here",
  "replace-me",
]);

export function loadConfig(): AgentConfig {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!secret || secret.trim() === "") {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET is not set. Copy the one-time plaintext from the Agent Games dashboard (Rotate Secret) and set it in the environment. The server will not start without it, and will never use a placeholder."
    );
  }
  if (FORBIDDEN_SECRETS.has(secret.trim().toLowerCase())) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET looks like a placeholder. Use the real platform-generated value from Rotate Secret."
    );
  }

  const kurierEnabled = envBool("KURIER_ENABLED", false);
  const kurierApiKey = process.env.KURIER_API_KEY ?? "";
  if (kurierEnabled && kurierApiKey.trim() === "") {
    throw new Error("KURIER_ENABLED=true but KURIER_API_KEY is not set.");
  }

  const requestTimeoutMs = envInt("REQUEST_TIMEOUT_MS", 60_000);
  const kurierPollTimeoutMs = envInt("KURIER_POLL_TIMEOUT_MS", 30_000);
  if (kurierEnabled && kurierPollTimeoutMs >= requestTimeoutMs) {
    throw new Error(
      `KURIER_POLL_TIMEOUT_MS (${kurierPollTimeoutMs}) must be smaller than REQUEST_TIMEOUT_MS (${requestTimeoutMs}) so Kurier polling can never push a response past the deadline.`
    );
  }

  return {
    port: envInt("PORT", 3000),
    hmacSecret: secret,
    vkHash: (process.env.GATEKEEPER_VK_HASH ?? REGISTERED_VK_HASH).trim(),
    wasmPath: process.env.CIRCUIT_WASM_PATH ?? "circuits/gatekeeper.wasm",
    zkeyPath: process.env.CIRCUIT_ZKEY_PATH ?? "circuits/gatekeeper_final.zkey",
    verificationKeyPath:
      process.env.VERIFICATION_KEY_PATH ?? "circuits/verification_key.json",
    kurierEnabled,
    kurierApiKey: kurierApiKey.trim(),
    kurierApiUrl: (process.env.KURIER_API_URL ?? "https://api.kurier.xyz/api/v1").replace(/\/$/, ""),
    kurierPollIntervalMs: envInt("KURIER_POLL_INTERVAL_MS", 5_000),
    kurierPollTimeoutMs,
    requestTimeoutMs,
    seenStorePath: process.env.SEEN_STORE_PATH ?? "data/seen.json",
    timestampSkewMs: envInt("TIMESTAMP_SKEW_MS", 300_000),
  };
}

/** Validate the circuit artifacts exist and are readable at startup.
 *  Throws with a clear message if anything is missing. Does not log secrets. */
export function validateCircuitArtifacts(cfg: AgentConfig): void {
  for (const [label, path] of [
    ["WASM", cfg.wasmPath],
    ["zkey", cfg.zkeyPath],
    ["verification key", cfg.verificationKeyPath],
  ] as const) {
    let buf: Buffer;
    try {
      buf = readFileSync(path);
    } catch {
      throw new Error(
        `Circuit artifact missing/unreadable (${label}): ${path}. ` +
          `Download gatekeeper.wasm / gatekeeper_final.zkey from https://agentgames.zkverify.io/circuits/ and export the verification key with snarkjs.`
      );
    }
    if (buf.length === 0) throw new Error(`Circuit artifact is empty (${label}): ${path}`);
  }
  // Sanity: wasm magic bytes "\0asm".
  const wasm = readFileSync(cfg.wasmPath);
  if (wasm[0] !== 0x00 || wasm[1] !== 0x61 || wasm[2] !== 0x73 || wasm[3] !== 0x6d) {
    throw new Error(`CIRCUIT_WASM_PATH does not look like a wasm module: ${cfg.wasmPath}`);
  }
}
