/**
 * HTTP server (Node.js stdlib only, no framework).
 *
 * Routes:
 *   POST /agent   — the registered agent endpoint (preflight + tasks).
 *   GET  /health  — { status: "ok", protocolVersion: "v1", vkHash }.
 *
 * /agent flow (in order):
 *   1. Read the RAW body as bytes (1 MiB cap).
 *   2. Verify HMAC-SHA256 over the raw body against the
 *      `x-agent-games-signature` header — BEFORE parsing JSON.
 *      Mismatch / missing header -> 401, signed error body.
 *   3. Parse JSON. Route by envelope `type`:
 *        agent-games.preflight.v1        -> { ok: true, protocolVersion: "v1" }
 *        agent-games.proof-gatekeeper.v1 -> decision + Groth16 proof
 *        anything else                   -> 400, signed error body.
 *   4. Task: deterministic decision, record proof_tx, generate the proof
 *      (both APPROVE and REJECT), optionally submit to Kurier, then respond
 *      — all inside the hard request deadline. Timeout -> REJECT / TIMEOUT.
 *   5. Every /agent response (success and error) is signed with
 *      `x-agent-games-signature` over the raw response body.
 *
 * Fail closed everywhere: any error, timeout, or uncertainty is a REJECT,
 * never an approval.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { decideTask } from "./decision.js";
import { PROTOCOL_VERSION, type AgentConfig } from "./config.js";
import { SIGNATURE_HEADER, signBody, verifySignature } from "./hmac.js";
import { submitAndFinalize } from "./kurier.js";
import { proveDecision } from "./prover.js";
import type { SeenStore } from "./seenStore.js";
import type {
  GatekeeperEnvelope,
  GatekeeperResponse,
  HealthResponse,
  PreflightResponse,
} from "./types.js";

const MAX_BODY_BYTES = 1_048_576; // 1 MiB

export interface ServerDeps {
  config: AgentConfig;
  seen: SeenStore;
}

function sendJson(res: ServerResponse, status: number, body: unknown, signSecret?: string): void {
  const raw = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "content-type": "application/json",
    ...(signSecret ? { [SIGNATURE_HEADER]: signBody(signSecret, raw) } : {}),
  });
  res.end(raw);
}

/** Signed error body for /agent (generic message — no internals leaked). */
function sendSignedError(
  res: ServerResponse,
  status: number,
  code: string,
  secret: string
): void {
  sendJson(res, status, { error: code }, secret);
}

async function readRawBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error("body too large");
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Full task pipeline: decide -> record proof_tx -> prove -> (Kurier) -> response.
 * Throws only on proof-generation failure (mapped to PROOF_FAILED by caller);
 * every other failure mode is a REJECT reason produced by decideTask.
 */
async function runTask(
  envelope: GatekeeperEnvelope,
  deps: ServerDeps,
  startedAtMs: number
): Promise<GatekeeperResponse> {
  const { config, seen } = deps;
  const mode = typeof envelope.mode === "string" ? envelope.mode : "competition";
  const proofTx = envelope.input?.proof_tx;

  const outcome = decideTask(envelope, {
    nowMs: Date.now(),
    timestampSkewMs: config.timestampSkewMs,
    isProofReused: (m, tx) => seen.isSeen(m, tx),
  });

  // Record the reference once a decision exists (both APPROVE and REJECT),
  // so any replay of this proof_tx is PROOF_REUSED.
  if (typeof proofTx === "string" && proofTx.trim() !== "") {
    seen.markSeen(mode, proofTx);
  }

  // PROOF_REUSED is an off-chain-only check: the circuit's verdict is a
  // function of the 13 on-chain inputs, and a replayed task passes all of
  // them, so the circuit cannot produce a REJECT proof for it. Returning
  // REJECT/PROOF_REUSED without a proof is the honest fail-closed answer
  // (correct decision +12, missing proof -2) — fabricating a proof by
  // altering the circuit inputs would make the public signals lie about
  // the task, which the platform would reject.
  if (outcome.reasonCode === "PROOF_REUSED") {
    console.log(`[agent] proof_tx reused, rejecting without proof task=${envelope.task_id}`);
    return {
      decision: "REJECT",
      reason_code: "PROOF_REUSED",
      ...(proofTx ? { proof_tx: proofTx } : {}),
    };
  }

  // Generate the proof for the decision. The circuit enforces
  // decision == computed verdict; a throw means our decision disagrees
  // with the circuit — fail closed, never approve.
  let proof: GatekeeperResponse["proof"];
  let publicSignals: string[] | undefined;
  try {
    const generated = await proveDecision(
      envelope.task_id,
      envelope.input,
      outcome.decision,
      config.wasmPath,
      config.zkeyPath
    );
    proof = generated.proof;
    publicSignals = generated.publicSignals;
  } catch (err) {
    console.error(
      `[agent] proof generation failed for task ${envelope.task_id} (${outcome.decision}/${outcome.reasonCode}): ${(err as Error).message}`
    );
    return {
      decision: "REJECT",
      reason_code: "PROOF_FAILED",
      ...(proofTx ? { proof_tx: proofTx } : {}),
    };
  }

  // Kurier confirmation (audit step). Bounded so it can never push the
  // response past the deadline; a failure here never changes the decision.
  let proofReference: string | undefined;
  if (config.kurierEnabled && proof && publicSignals) {
    const remainingMs = config.requestTimeoutMs - (Date.now() - startedAtMs) - 2_000;
    if (remainingMs > 0) {
      const kurier = await submitAndFinalize(proof, publicSignals, {
        apiUrl: config.kurierApiUrl,
        apiKey: config.kurierApiKey,
        vkHash: config.vkHash,
        pollIntervalMs: config.kurierPollIntervalMs,
        pollTimeoutMs: Math.min(config.kurierPollTimeoutMs, remainingMs),
      });
      if (kurier) {
        console.log(
          `[agent] kurier job ${kurier.jobId} status=${kurier.status} task=${envelope.task_id}`
        );
        proofReference = kurier.jobId;
        if (kurier.proofReference) proofReference = kurier.proofReference;
      } else {
        console.warn(`[agent] kurier submission failed/unavailable task=${envelope.task_id}`);
      }
    }
  }

  return {
    decision: outcome.decision,
    reason_code: outcome.reasonCode,
    proof,
    public_signals: publicSignals,
    ...(proofTx ? { proof_tx: proofTx } : {}),
    ...(proofReference ? { proofReference } : {}),
  };
}

async function handleAgent(req: IncomingMessage, res: ServerResponse, deps: ServerDeps): Promise<void> {
  const { config } = deps;
  const startedAtMs = Date.now();

  let raw: Buffer;
  try {
    raw = await readRawBody(req);
  } catch {
    sendSignedError(res, 413, "body_too_large", config.hmacSecret);
    return;
  }

  // HMAC over the RAW body, before any parsing.
  const signature = req.headers[SIGNATURE_HEADER] as string | undefined;
  if (!verifySignature(config.hmacSecret, raw, signature)) {
    sendSignedError(res, 401, "invalid_signature", config.hmacSecret);
    return;
  }

  let envelope: unknown;
  try {
    envelope = JSON.parse(raw.toString("utf8")) as unknown;
  } catch {
    sendSignedError(res, 400, "invalid_json", config.hmacSecret);
    return;
  }

  if (typeof envelope !== "object" || envelope === null) {
    sendSignedError(res, 400, "invalid_envelope", config.hmacSecret);
    return;
  }
  const type = (envelope as { type?: unknown }).type;

  // Preflight handshake.
  if (type === "agent-games.preflight.v1") {
    const body: PreflightResponse = { ok: true, protocolVersion: PROTOCOL_VERSION };
    sendJson(res, 200, body, config.hmacSecret);
    return;
  }

  // Task.
  if (type === "agent-games.proof-gatekeeper.v1") {
    const task = envelope as GatekeeperEnvelope;
    const proofTx =
      typeof task.input?.proof_tx === "string" ? task.input.proof_tx : undefined;

    const timeoutResponse: GatekeeperResponse = {
      decision: "REJECT",
      reason_code: "TIMEOUT",
      ...(proofTx ? { proof_tx: proofTx } : {}),
    };
    const result = await Promise.race([
      runTask(task, deps, startedAtMs),
      sleep(config.requestTimeoutMs).then(() => timeoutResponse),
    ]);
    if (result.reason_code === "TIMEOUT") {
      console.warn(`[agent] request deadline exceeded task=${task.task_id ?? "?"}`);
    }
    sendJson(res, 200, result, config.hmacSecret);
    return;
  }

  sendSignedError(res, 400, "unknown_type", config.hmacSecret);
}

export function createAgentServer(deps: ServerDeps) {
  const { config } = deps;
  const server = createServer((req, res) => {
    void (async () => {
      try {
        if (req.method === "GET" && req.url === "/health") {
          const body: HealthResponse = {
            status: "ok",
            protocolVersion: PROTOCOL_VERSION,
            vkHash: config.vkHash,
          };
          sendJson(res, 200, body);
          return;
        }
        if (req.method === "POST" && req.url === "/agent") {
          await handleAgent(req, res, deps);
          return;
        }
        sendJson(res, 404, { error: "not_found" });
      } catch (err) {
        console.error(`[agent] unhandled error: ${(err as Error).message}`);
        try {
          // Fail closed and signed on /agent; plain 500 elsewhere.
          if (req.url === "/agent") sendSignedError(res, 500, "internal_error", config.hmacSecret);
          else sendJson(res, 500, { error: "internal_error" });
        } catch {
          // Response already sent — nothing more to do.
        }
      }
    })();
  });
  return server;
}
