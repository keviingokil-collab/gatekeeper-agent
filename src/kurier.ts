/**
 * Kurier submission (zkVerify REST verification) — the recommended path from
 * the /build guide.
 *
 * Submit:  POST {apiUrl}/submit-proof/{apiKey}
 *          body: { proofType: "groth16", vkRegistered: true,
 *                  proofOptions: { library: "snarkjs", curve: "bn128" },
 *                  proofData: { proof, publicSignals, vk: registeredVkHash } }
 * Poll:    GET  {apiUrl}/job-status/{apiKey}/{jobId}
 *          (zkVerify docs: https://docs.zkverify.io/overview/getting-started/kurier)
 *          until status === "Finalized" (or a terminal failure), or timeout.
 *
 * The gatekeeper vkHash is already registered on zkVerify mainnet
 * (the /build page shows it as registered), and the submit body sets
 * vkRegistered: true — so no register-vk call is made here.
 *
 * Kurier is a confirmation/audit step only. It NEVER changes the decision
 * and NEVER delays the response past the request deadline: the caller gives
 * it a bounded poll budget, and any failure/timeout is logged and the
 * decision + proof are still returned. proofReference is the Kurier jobId
 * when a job was accepted.
 */

import type { Groth16Proof } from "./types.js";

export interface KurierResult {
  jobId: string;
  status: "Finalized" | "Submitted" | "IncludedInBlock" | "Failed" | "Unknown";
  /** Transaction / reference returned by Kurier, when present. */
  proofReference?: string;
}

export interface KurierConfig {
  apiUrl: string;
  apiKey: string;
  vkHash: string;
  pollIntervalMs: number;
  pollTimeoutMs: number;
}

const TERMINAL_FAILURE = new Set(["failed", "error", "rejected", "cancelled"]);

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchJson(url: string, init: RequestInit, timeoutMs: number): Promise<unknown> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    const text = await res.text();
    let data: unknown = null;
    try {
      data = text ? (JSON.parse(text) as unknown) : null;
    } catch {
      data = null;
    }
    if (!res.ok) {
      throw new Error(`Kurier HTTP ${res.status}: ${String(text).slice(0, 200)}`);
    }
    return data;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Submit a proof to Kurier and poll until Finalized (or timeout/failure).
 * Returns null when Kurier is unreachable, rejects the proof, or the poll
 * budget is exhausted — the caller still returns the decision + proof.
 * Never throws for a Kurier-side problem (only for programmer errors).
 */
export async function submitAndFinalize(
  proof: Groth16Proof,
  publicSignals: string[],
  cfg: KurierConfig
): Promise<KurierResult | null> {
  try {
    const submitUrl = `${cfg.apiUrl}/submit-proof/${cfg.apiKey}`;
    const submitted = (await fetchJson(
      submitUrl,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          proofType: "groth16",
          vkRegistered: true,
          proofOptions: { library: "snarkjs", curve: "bn128" },
          proofData: { proof, publicSignals, vk: cfg.vkHash },
        }),
      },
      15_000
    )) as Record<string, unknown> | null;

    const jobId = String(
      submitted?.jobId ?? submitted?.job_id ?? submitted?.id ?? ""
    ).trim();
    if (!jobId) return null;

    const started = Date.now();
    let status: KurierResult["status"] = "Submitted";
    let proofReference: string | undefined;
    while (Date.now() - started < cfg.pollTimeoutMs) {
      const jobUrl = `${cfg.apiUrl}/job-status/${cfg.apiKey}/${encodeURIComponent(jobId)}`;
      const job = (await fetchJson(jobUrl, { method: "GET" }, 10_000)) as Record<
        string,
        unknown
      > | null;
      const rawStatus = String(job?.status ?? job?.state ?? "").trim();
      const ref = job?.proofReference ?? job?.txHash ?? job?.transactionHash ?? job?.proofTx;
      if (typeof ref === "string" && ref.trim() !== "") proofReference = ref.trim();
      if (rawStatus === "Finalized") {
        status = "Finalized";
        break;
      }
      if (TERMINAL_FAILURE.has(rawStatus.toLowerCase())) {
        status = "Failed";
        break;
      }
      if (rawStatus === "IncludedInBlock") status = "IncludedInBlock";
      else if (rawStatus !== "") status = "Submitted";
      await sleep(cfg.pollIntervalMs);
    }
    return { jobId, status, proofReference };
  } catch {
    return null;
  }
}
