/**
 * HMAC-SHA256 signing / verification for the Agent Games protocol.
 *
 * - Inbound: compute HMAC-SHA256 over the RAW request body bytes and compare
 *   (timing-safe) to the `x-agent-games-signature` header, BEFORE parsing JSON.
 * - Outbound: compute HMAC-SHA256 over the RAW response body bytes and set
 *   it as the `x-agent-games-signature` header.
 *
 * Signature encoding: the platform sends a hex digest. We accept a hex digest
 * with or without a `sha256=` prefix, and (as a fallback) a base64 digest of
 * the same 32 bytes. Responses are always signed with the plain hex digest.
 * Secrets are never logged.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

/** HMAC-SHA256 of `body` under `secret`, returned as a lowercase hex string. */
export function signBody(secret: string, body: Buffer | string): string {
  const data = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  return createHmac("sha256", secret).update(data).digest("hex");
}

/**
 * Timing-safe verification of a signature header against the raw body.
 * Returns false (never throws) on any mismatch, missing value, or malformed
 * encoding — callers treat false as "reject the request".
 */
export function verifySignature(secret: string, body: Buffer, signature: string | undefined): boolean {
  if (!signature || signature.trim() === "") return false;
  let candidate = signature.trim();
  if (candidate.toLowerCase().startsWith("sha256=")) candidate = candidate.slice("sha256=".length);

  const expectedHex = signBody(secret, body);
  const expectedBuf = Buffer.from(expectedHex, "hex");

  // Hex digest (the platform's format).
  if (/^[0-9a-fA-F]{64}$/.test(candidate)) {
    const got = Buffer.from(candidate.toLowerCase(), "hex");
    return got.length === expectedBuf.length && timingSafeEqual(got, expectedBuf);
  }
  // Base64 fallback (same 32 bytes).
  try {
    const got = Buffer.from(candidate, "base64");
    if (got.length === 32) {
      return timingSafeEqual(got, expectedBuf);
    }
  } catch {
    // fall through to false
  }
  return false;
}
