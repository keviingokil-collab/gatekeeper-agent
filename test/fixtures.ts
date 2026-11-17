/**
 * Test fixtures — concrete (non-truncated) values, matching the /build
 * sample task. Timestamps are built relative to a base time so the
 * issued_at / deadline_at checks pass when the harness runs.
 *
 * The registered vk is the real gatekeeper vkHash from /api/circuit-info.
 */

import type { GatekeeperEnvelope } from "../src/types.js";

export const REAL_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
export const OTHER_VK_HASH =
  "0x1313131313131313131313131313131313131313131313131313131313131313";

export const RECIPIENT_A = "0x1111111111111111111111111111111111111111";
export const RECIPIENT_B = "0x2222222222222222222222222222222222222222";

function tx(n: string): string {
  // A distinct 32-byte proof_tx per fixture ("0x" + 64 hex chars).
  return "0x" + n.repeat(64).slice(0, 64);
}

export function baseInput(): GatekeeperEnvelope["input"] {
  return {
    registered_vk: REAL_VK_HASH,
    proof_vk: REAL_VK_HASH,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: RECIPIENT_A,
    condition_recipient: RECIPIENT_A,
    amount: "500",
    max_transfer: "1000",
    proof_tx: tx("a"),
  };
}

export interface FixtureSet {
  valid: GatekeeperEnvelope;
  vkSubstitution: GatekeeperEnvelope;
  thresholdMismatch: GatekeeperEnvelope;
  expired: GatekeeperEnvelope;
  recipientMismatch: GatekeeperEnvelope;
  amountOverflow: GatekeeperEnvelope;
}

/** Build all fixtures with issued_at/deadline_at relative to `nowMs`. */
export function buildFixtures(nowMs: number): FixtureSet {
  const issuedAt = new Date(nowMs - 60_000).toISOString();
  const deadlineAt = new Date(nowMs + 120_000).toISOString();
  const env = (taskId: string, input: GatekeeperEnvelope["input"]): GatekeeperEnvelope => ({
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: issuedAt,
    deadline_at: deadlineAt,
    input,
  });

  const valid = env("gk_test_valid_001", baseInput());

  const vkSubstitution = env("gk_test_vksub_001", {
    ...baseInput(),
    proof_vk: OTHER_VK_HASH, // the /build sample: proof_vk != registered_vk
    proof_tx: tx("b"),
  });

  const thresholdMismatch = env("gk_test_threshold_001", {
    ...baseInput(),
    public_balance: "500", // below minimum 1000
    proof_tx: tx("c"),
  });

  const expired = env("gk_test_expired_001", {
    ...baseInput(),
    current_block: 8430000, // == expiry_block -> expired
    proof_tx: tx("d"),
  });

  const recipientMismatch = env("gk_test_recipient_001", {
    ...baseInput(),
    recipient: RECIPIENT_B, // != condition_recipient
    proof_tx: tx("e"),
  });

  const amountOverflow = env("gk_test_amount_001", {
    ...baseInput(),
    amount: "1500", // > max_transfer 1000
    proof_tx: tx("f"),
  });

  return { valid, vkSubstitution, thresholdMismatch, expired, recipientMismatch, amountOverflow };
}
