/**
 * Local Groth16 proof generation with snarkjs (official gatekeeper circuit).
 *
 * Validated input mapping (13 signals, Circom 2.2.3, BN128):
 *   taskId             = keccak256(utf8(task_id)) mod p
 *   minimum            = decimal string from the task
 *   publicBalance      = decimal string from the task
 *   expiryBlock        = decimal string from the task
 *   currentBlock       = decimal string from the task
 *   recipient          = BigInt(address) as decimal string
 *   conditionRecipient = BigInt(address) as decimal string
 *   amount             = decimal string from the task
 *   maxTransfer        = decimal string from the task
 *   registeredVkHash   = BigInt(hex) mod p as decimal string
 *   proofVkHash        = BigInt(hex) mod p as decimal string
 *   salt               = random 32 bytes mod p (private, fresh per task)
 *   decision           = "1" for APPROVE, "0" for REJECT
 *
 * The circuit enforces decision == its own computed verdict (approve iff
 * every check passes). A proof is generated for BOTH approve and reject —
 * a REJECT proof is required, not optional. If fullProve throws, the
 * decision does not match the circuit verdict; the caller must fail closed
 * (REJECT / PROOF_FAILED) and never approve.
 *
 * Public signals (13) are returned exactly as snarkjs returns them — never
 * reordered or reinterpreted. [0] is the Poseidon(salt, taskId) binding
 * commitment; the rest are the public fields in circuit order.
 */

import { randomBytes } from "node:crypto";
import { keccak256, toUtf8Bytes } from "ethers";
import * as snarkjs from "snarkjs";
import type { Decision, GatekeeperTaskInput, Groth16Proof } from "./types.js";

/** BN128 (alt_bn128) scalar field prime. */
export const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

export interface GeneratedProof {
  proof: Groth16Proof;
  publicSignals: string[];
}

function fieldElementFromHex(hex: string): string {
  const s = hex.trim();
  if (!/^0x[0-9a-fA-F]+$/.test(s)) throw new Error("not a 0x hex value");
  return (BigInt(s) % FIELD_PRIME).toString();
}

function addressToField(address: string): string {
  const s = address.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) throw new Error("not a 0x address");
  return BigInt(s).toString();
}

function freshSalt(): string {
  // Random 32 bytes mod p; re-roll the negligible chance of 0.
  for (;;) {
    const salt = BigInt("0x" + randomBytes(32).toString("hex")) % FIELD_PRIME;
    if (salt !== 0n) return salt.toString();
  }
}

/** Build the 13 circuit inputs for a task + decision. Throws on bad input. */
export function buildCircuitInput(
  taskId: string,
  input: GatekeeperTaskInput,
  decision: Decision
): Record<string, string> {
  const taskIdField = (BigInt(keccak256(toUtf8Bytes(taskId))) % FIELD_PRIME).toString();
  return {
    taskId: taskIdField,
    minimum: BigInt(String(input.minimum).trim()).toString(),
    publicBalance: BigInt(String(input.public_balance).trim()).toString(),
    expiryBlock: BigInt(String(input.expiry_block).trim()).toString(),
    currentBlock: BigInt(String(input.current_block).trim()).toString(),
    recipient: addressToField(input.recipient),
    conditionRecipient: addressToField(input.condition_recipient),
    amount: BigInt(String(input.amount).trim()).toString(),
    maxTransfer: BigInt(String(input.max_transfer).trim()).toString(),
    registeredVkHash: fieldElementFromHex(input.registered_vk),
    proofVkHash: fieldElementFromHex(input.proof_vk),
    salt: freshSalt(),
    decision: decision === "APPROVE" ? "1" : "0",
  };
}

/** Generate the Groth16 proof for a decision. Throws if the circuit rejects
 *  the (inputs, decision) pair — the caller must fail closed. */
export async function proveDecision(
  taskId: string,
  input: GatekeeperTaskInput,
  decision: Decision,
  wasmPath: string,
  zkeyPath: string
): Promise<GeneratedProof> {
  const circuitInput = buildCircuitInput(taskId, input, decision);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, wasmPath, zkeyPath);
  if (!Array.isArray(publicSignals) || publicSignals.length !== 13) {
    throw new Error(`unexpected publicSignals length: ${publicSignals?.length}`);
  }
  return { proof: proof as Groth16Proof, publicSignals: publicSignals.map(String) };
}
