/**
 * Types for the Proof Gatekeeper agent (zkVerify Agent Games).
 * Schemas follow the official /build field guide exactly; nothing here is
 * invented. Unknown/extra fields in inbound envelopes are ignored.
 */

export type Decision = "APPROVE" | "REJECT";

export type ReasonCode =
  | "OK"
  | "INVALID_TASK"
  | "VK_SUBSTITUTION"
  | "THRESHOLD_MISMATCH"
  | "EXPIRED"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW"
  | "PROOF_REUSED"
  | "PROOF_FAILED"
  | "TIMEOUT";

/** The `input` object inside a proof-gatekeeper task envelope. */
export interface GatekeeperTaskInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number | string;
  current_block: number | string;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  proof_tx: string;
}

/** Inbound proof-gatekeeper task envelope (POST /agent). */
export interface GatekeeperEnvelope {
  type: "agent-games.proof-gatekeeper.v1";
  task_id: string;
  mode: "competition" | "practice" | string;
  issued_at: string;
  deadline_at: string;
  input: GatekeeperTaskInput;
}

/** Inbound preflight envelope (POST /agent). */
export interface PreflightEnvelope {
  type: "agent-games.preflight.v1";
  agent_id: string;
  issued_at: string;
  nonce: string;
}

/** A snarkjs Groth16 proof (pi_a / pi_b / pi_c, protocol, curve). */
export interface Groth16Proof {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: "groth16";
  curve: "bn128";
}

/** Outbound response for a task. proof / public_signals are present on every
 *  decision whose proof was generated (both APPROVE and REJECT). They are
 *  absent only when proof generation itself failed (PROOF_FAILED) or the
 *  request timed out (TIMEOUT) — in those cases the decision is REJECT and
 *  the absence of a proof is the fail-closed cost, not a silent approval. */
export interface GatekeeperResponse {
  decision: Decision;
  reason_code: ReasonCode;
  proof?: Groth16Proof;
  public_signals?: string[];
  proof_tx?: string;
  proofReference?: string;
}

/** Preflight response. */
export interface PreflightResponse {
  ok: true;
  protocolVersion: "v1";
}

/** Health endpoint payload. */
export interface HealthResponse {
  status: "ok";
  protocolVersion: "v1";
  vkHash: string;
}
