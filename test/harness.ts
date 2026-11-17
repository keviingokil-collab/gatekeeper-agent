/**
 * Integration test harness for the Proof Gatekeeper agent.
 *
 * Starts the compiled server as a child process (test HMAC secret, Kurier
 * disabled, an isolated seen-store file), then replays sample envelopes
 * over real HTTP and asserts, for each case:
 *   - the HTTP status,
 *   - decision + reason_code,
 *   - the response HMAC (`x-agent-games-signature`) is valid over the raw body,
 *   - the returned Groth16 proof verifies against circuits/verification_key.json
 *     (snarkjs groth16 verify).
 *
 * One documented exception: PROOF_REUSED. The circuit's verdict is a
 * function of the 13 on-chain inputs, and a replayed task passes all of
 * them, so the circuit cannot produce a REJECT proof for it. The agent
 * correctly returns REJECT/PROOF_REUSED with NO proof; the harness asserts
 * the absence of the proof (and the correct decision/reason/HMAC) instead
 * of a verifying proof.
 *
 * Run: npm test   (builds first, then runs this file with node)
 */

import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as snarkjs from "snarkjs";
import { signBody, verifySignature } from "../src/hmac.js";
import type { GatekeeperResponse, Groth16Proof } from "../src/types.js";
import { buildFixtures } from "./fixtures.js";

const TEST_SECRET = "test-harness-secret-do-not-use-in-production";
const PORT = 3101;
const BASE = `http://127.0.0.1:${PORT}`;
const SEEN_PATH = join(tmpdir(), `gatekeeper-test-seen-${process.pid}.json`);
const VK_PATH = "circuits/verification_key.json";

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, cond: boolean, detail = ""): void {
  if (cond) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

interface Posted {
  status: number;
  raw: Buffer;
  signature: string | undefined;
  body: Record<string, unknown>;
}

async function postAgent(envelope: unknown, secret: string = TEST_SECRET): Promise<Posted> {
  const raw = Buffer.from(JSON.stringify(envelope), "utf8");
  const res = await fetch(`${BASE}/agent`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": signBody(secret, raw),
    },
    body: raw,
  });
  const buf = Buffer.from(await res.arrayBuffer());
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(buf.toString("utf8")) as Record<string, unknown>;
  } catch {
    body = { _unparsable: buf.toString("utf8").slice(0, 200) };
  }
  return {
    status: res.status,
    raw: buf,
    signature: res.headers.get("x-agent-games-signature") ?? undefined,
    body,
  };
}

/** Assert the response HMAC is valid over the raw body. */
function checkSignature(name: string, p: Posted): void {
  check(`${name}: response HMAC valid`, verifySignature(TEST_SECRET, p.raw, p.signature));
}

/** Assert the returned proof verifies against the official verification key. */
async function checkProof(
  name: string,
  p: Posted,
  vk: unknown
): Promise<void> {
  const body = p.body as unknown as GatekeeperResponse;
  const proof = body.proof as Groth16Proof | undefined;
  const publicSignals = body.public_signals as string[] | undefined;
  check(`${name}: proof present`, proof !== undefined && Array.isArray(publicSignals));
  if (!proof || !publicSignals) return;
  check(`${name}: 13 public signals`, publicSignals.length === 13, `got ${publicSignals.length}`);
  let ok = false;
  try {
    ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  } catch (err) {
    ok = false;
    console.log(`    verify error: ${(err as Error).message}`);
  }
  check(`${name}: snarkjs groth16 verify OK`, ok);
}

async function waitForHealth(timeoutMs = 30_000): Promise<boolean> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

async function main(): Promise<number> {
  console.log("== Proof Gatekeeper harness ==");
  rmSync(SEEN_PATH, { force: true });

  const child: ChildProcess = spawn(process.execPath, ["dist/src/index.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      KURIER_ENABLED: "false",
      SEEN_STORE_PATH: SEEN_PATH,
      REQUEST_TIMEOUT_MS: "60000",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  child.stdout?.on("data", (d: Buffer) => {
    serverLog += d.toString();
  });
  child.stderr?.on("data", (d: Buffer) => {
    serverLog += d.toString();
  });

  try {
    const up = await waitForHealth();
    check("server starts and /health responds", up);
    if (!up) {
      console.log("server log:\n" + serverLog);
      return 1;
    }

    const vk = JSON.parse(readFileSync(VK_PATH, "utf8")) as unknown;
    const fx = buildFixtures(Date.now());

    // --- Preflight ---
    console.log("-- preflight --");
    const preflight = {
      type: "agent-games.preflight.v1",
      agent_id: "agt_test",
      issued_at: new Date().toISOString(),
      nonce: "abc123",
    };
    const pf = await postAgent(preflight);
    check("preflight: 200", pf.status === 200, `got ${pf.status}`);
    check("preflight: ok=true, protocolVersion=v1", pf.body.ok === true && pf.body.protocolVersion === "v1");
    checkSignature("preflight", pf);

    const pfBad = await postAgent(preflight, "wrong-secret");
    check("preflight with bad signature: 401", pfBad.status === 401, `got ${pfBad.status}`);

    // --- VK_SUBSTITUTION trap (the /build sample) ---
    console.log("-- VK_SUBSTITUTION trap --");
    const vkSub = await postAgent(fx.vkSubstitution);
    check("VK_SUBSTITUTION: 200", vkSub.status === 200, `got ${vkSub.status}`);
    check(
      "VK_SUBSTITUTION: REJECT / VK_SUBSTITUTION",
      vkSub.body.decision === "REJECT" && vkSub.body.reason_code === "VK_SUBSTITUTION",
      JSON.stringify(vkSub.body).slice(0, 200)
    );
    check("VK_SUBSTITUTION: proof_tx echoed", vkSub.body.proof_tx === fx.vkSubstitution.input.proof_tx);
    checkSignature("VK_SUBSTITUTION", vkSub);
    await checkProof("VK_SUBSTITUTION", vkSub, vk);

    // --- Valid task ---
    console.log("-- valid task --");
    const valid = await postAgent(fx.valid);
    check("valid: 200", valid.status === 200, `got ${valid.status}`);
    check(
      "valid: APPROVE / OK",
      valid.body.decision === "APPROVE" && valid.body.reason_code === "OK",
      JSON.stringify(valid.body).slice(0, 200)
    );
    checkSignature("valid", valid);
    await checkProof("valid", valid, vk);

    // --- Remaining trap varieties ---
    console.log("-- trap varieties --");
    const traps: Array<[string, unknown, string]> = [
      ["THRESHOLD_MISMATCH", fx.thresholdMismatch, "THRESHOLD_MISMATCH"],
      ["EXPIRED", fx.expired, "EXPIRED"],
      ["RECIPIENT_MISMATCH", fx.recipientMismatch, "RECIPIENT_MISMATCH"],
      ["AMOUNT_OVERFLOW", fx.amountOverflow, "AMOUNT_OVERFLOW"],
    ];
    for (const [label, envelope, code] of traps) {
      const r = await postAgent(envelope);
      check(`${label}: 200`, r.status === 200, `got ${r.status}`);
      check(
        `${label}: REJECT / ${code}`,
        r.body.decision === "REJECT" && r.body.reason_code === code,
        JSON.stringify(r.body).slice(0, 200)
      );
      checkSignature(label, r);
      await checkProof(label, r, vk);
    }

    // --- PROOF_REUSED: replay the valid task (same proof_tx) ---
    console.log("-- PROOF_REUSED (replay) --");
    const replay = await postAgent(fx.valid);
    check("PROOF_REUSED: 200", replay.status === 200, `got ${replay.status}`);
    check(
      "PROOF_REUSED: REJECT / PROOF_REUSED",
      replay.body.decision === "REJECT" && replay.body.reason_code === "PROOF_REUSED",
      JSON.stringify(replay.body).slice(0, 200)
    );
    checkSignature("PROOF_REUSED", replay);
    // No proof is expected here (see the header comment): the circuit
    // cannot prove an off-chain-only rejection.
    check(
      "PROOF_REUSED: no proof attached (circuit cannot prove an off-chain-only rejection)",
      (replay.body as unknown as GatekeeperResponse).proof === undefined
    );

    // --- Unknown type / missing signature ---
    console.log("-- malformed --");
    const unknown = await postAgent({ type: "agent-games.nope.v1" });
    check("unknown type: 400", unknown.status === 400, `got ${unknown.status}`);
    const noSigRaw = Buffer.from(JSON.stringify(fx.valid), "utf8");
    const noSigRes = await fetch(`${BASE}/agent`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: noSigRaw,
    });
    check("missing signature: 401", noSigRes.status === 401, `got ${noSigRes.status}`);

    console.log(`\n== ${passed} passed, ${failed} failed ==`);
    if (failed > 0) console.log("failed: " + failures.join(", "));
    return failed > 0 ? 1 : 0;
  } finally {
    child.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 500));
    rmSync(SEEN_PATH, { force: true });
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error("harness crashed:", err);
    process.exit(2);
  });
