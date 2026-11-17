/**
 * Deterministic decision logic for Proof Gatekeeper.
 *
 * NO language model and no randomness in this path — pure BigInt / string
 * comparisons over the task envelope. APPROVE only when EVERY check passes;
 * otherwise REJECT with the first failing check's reason_code (order below
 * is the evaluation order). Any missing/invalid field, parse error, or
 * exception fails closed to REJECT.
 *
 * Check order (first failure wins):
 *   1. INVALID_TASK        — task_id present, issued_at parseable and not in
 *                             the future beyond skew, deadline_at not passed.
 *   2. VK_SUBSTITUTION     — proof_vk == registered_vk (case-insensitive).
 *   3. THRESHOLD_MISMATCH  — public_balance >= minimum.
 *   4. EXPIRED             — current_block < expiry_block.
 *   5. RECIPIENT_MISMATCH  — recipient == condition_recipient (case-insensitive).
 *   6. AMOUNT_OVERFLOW     — 0 < amount <= max_transfer.
 *   7. PROOF_REUSED        — proof_tx not already seen (mode-scoped).
 *
 * The proof_tx replay check is supplied by the caller (SeenStore) so this
 * module stays pure and unit-testable.
 */

import type { Decision, GatekeeperEnvelope, GatekeeperTaskInput, ReasonCode } from "./types.js";

export interface DecisionOutcome {
  decision: Decision;
  reasonCode: ReasonCode;
}

export interface DecisionContext {
  /** "now" (ms since epoch) — injectable for tests. */
  nowMs: number;
  /** Allowed clock skew for issued_at in the future (ms). */
  timestampSkewMs: number;
  /** True when this (mode, proof_tx) was already decided before. */
  isProofReused: (mode: string, proofTx: string) => boolean;
}

function toBigInt(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("not an integer");
    return BigInt(value);
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (s === "") throw new Error("empty numeric string");
    return BigInt(s);
  }
  throw new Error("not a number");
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim() !== "";
}

/** Pure decision function. Never throws — every failure is a REJECT. */
export function decideTask(envelope: unknown, ctx: DecisionContext): DecisionOutcome {
  try {
    return decideTaskInner(envelope, ctx);
  } catch {
    // Any unexpected shape/parse problem fails closed.
    return { decision: "REJECT", reasonCode: "INVALID_TASK" };
  }
}

function decideTaskInner(envelope: unknown, ctx: DecisionContext): DecisionOutcome {
  const reject = (reasonCode: ReasonCode): DecisionOutcome => ({ decision: "REJECT", reasonCode });

  if (typeof envelope !== "object" || envelope === null) return reject("INVALID_TASK");
  const env = envelope as Partial<GatekeeperEnvelope>;

  // --- 1. Task signature/timestamp validity (HMAC itself was verified by the
  // transport layer before this function is called). ---
  if (!isNonEmptyString(env.task_id)) return reject("INVALID_TASK");
  if (!isNonEmptyString(env.issued_at) || !isNonEmptyString(env.deadline_at)) {
    return reject("INVALID_TASK");
  }
  const issuedAt = Date.parse(env.issued_at);
  const deadlineAt = Date.parse(env.deadline_at);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(deadlineAt)) return reject("INVALID_TASK");
  if (issuedAt > ctx.nowMs + ctx.timestampSkewMs) return reject("INVALID_TASK");
  if (ctx.nowMs > deadlineAt) return reject("INVALID_TASK");

  const input = env.input as Partial<GatekeeperTaskInput> | undefined;
  if (typeof input !== "object" || input === null) return reject("INVALID_TASK");
  const required = [
    "registered_vk",
    "proof_vk",
    "minimum",
    "public_balance",
    "expiry_block",
    "current_block",
    "recipient",
    "condition_recipient",
    "amount",
    "max_transfer",
    "proof_tx",
  ] as const;
  for (const key of required) {
    const v = input[key];
    if (v === undefined || v === null || (typeof v === "string" && v.trim() === "")) {
      return reject("INVALID_TASK");
    }
  }

  // --- 2. VK matches the registered key. ---
  const registeredVk = String(input.registered_vk).trim().toLowerCase();
  const proofVk = String(input.proof_vk).trim().toLowerCase();
  if (proofVk !== registeredVk) return reject("VK_SUBSTITUTION");

  // --- 3. Threshold: public_balance >= minimum. ---
  let minimum: bigint;
  let publicBalance: bigint;
  try {
    minimum = toBigInt(input.minimum);
    publicBalance = toBigInt(input.public_balance);
  } catch {
    return reject("INVALID_TASK");
  }
  if (publicBalance < minimum) return reject("THRESHOLD_MISMATCH");

  // --- 4. Not expired: current_block < expiry_block. ---
  let expiryBlock: bigint;
  let currentBlock: bigint;
  try {
    expiryBlock = toBigInt(input.expiry_block);
    currentBlock = toBigInt(input.current_block);
  } catch {
    return reject("INVALID_TASK");
  }
  if (currentBlock >= expiryBlock) return reject("EXPIRED");

  // --- 5. Recipient matches the condition. ---
  const recipient = String(input.recipient).trim().toLowerCase();
  const conditionRecipient = String(input.condition_recipient).trim().toLowerCase();
  if (recipient !== conditionRecipient) return reject("RECIPIENT_MISMATCH");

  // --- 6. Amount within cap: 0 < amount <= max_transfer. ---
  let amount: bigint;
  let maxTransfer: bigint;
  try {
    amount = toBigInt(input.amount);
    maxTransfer = toBigInt(input.max_transfer);
  } catch {
    return reject("INVALID_TASK");
  }
  if (amount <= 0n || amount > maxTransfer) return reject("AMOUNT_OVERFLOW");

  // --- 7. Proof reference not reused (mode-scoped). ---
  const proofTx = String(input.proof_tx).trim();
  const mode = typeof env.mode === "string" ? env.mode : "competition";
  if (ctx.isProofReused(mode, proofTx)) return reject("PROOF_REUSED");

  return { decision: "APPROVE", reasonCode: "OK" };
}
