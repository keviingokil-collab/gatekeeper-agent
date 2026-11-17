# Proof Gatekeeper Agent — zkVerify Agent Games

A public HTTPS endpoint that judges signed transfer tasks and proves every
decision with a local Groth16 zero-knowledge proof (snarkjs, Circom 2.x,
BN128), for the **Proof Gatekeeper** track of the zkVerify Agent Games
(Season 01, 21 Oct – 21 Nov 2026).

The platform POSTs a signed task envelope; the agent decides **APPROVE** or
**REJECT** and returns the decision, a reason code, and the Groth16 proof +
public signals, all signed with HMAC-SHA256. The platform re-verifies the
proof against its own registered verification key and scores the decision
independently — the circuit is the referee.

## How it works

```
platform --POST /agent (HMAC-signed)--> agent
  1. Verify HMAC-SHA256 over the RAW body (before parsing JSON). 401 on mismatch.
  2. Route by envelope `type`: preflight | proof-gatekeeper task.
  3. Deterministic decision (pure BigInt/string checks, no LLM):
       INVALID_TASK -> VK_SUBSTITUTION -> THRESHOLD_MISMATCH -> EXPIRED
       -> RECIPIENT_MISMATCH -> AMOUNT_OVERFLOW -> PROOF_REUSED
     APPROVE only if every check passes; otherwise REJECT with the first
     failing check's reason code. Fail closed on any error or timeout.
  4. Generate the Groth16 proof locally with the official gatekeeper
     circuit (13 inputs; decision is proved for BOTH approve and reject).
  5. Optionally submit the proof to Kurier (zkVerify) and poll until
     Finalized; Kurier never changes the decision or the deadline.
  6. Respond signed (x-agent-games-signature over the raw response body).
```

Scoring (per the /build guide): correct decision +12, approving a trap −6,
rejecting a valid request −3, timeout/offline −2, proof fails to verify −2,
plus a reliability bonus (verified proofs / tasks).

## Quickstart

```bash
npm install
cp .env.example .env        # then fill in AGENT_GAMES_HMAC_SECRET (see below)
npm test                    # build + full integration harness (48 checks)
npm start                   # serve on $PORT (default 3000)
```

### Get the HMAC secret

Dashboard → **Rotate Secret** → copy the one-time plaintext → set it as
`AGENT_GAMES_HMAC_SECRET` in `.env` (or in your host's secret store).
The server **refuses to start** without it and never accepts a placeholder.
Rotate it on the dashboard after deploying, then restart the agent, then
run preflight from the dashboard — preflight must pass before the platform
marks the agent active.

### Register the endpoint

Deploy the service to a public HTTPS URL, then register the **full handler
path** (e.g. `https://your-host/agent` — not just the root domain) on the
dashboard. A root path that returns 404 fails preflight and every task.

## Configuration (environment only)

| Variable | Default | Notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | — | **Required.** Platform value from Rotate Secret. |
| `PORT` | `3000` | |
| `REQUEST_TIMEOUT_MS` | `60000` | Hard per-request deadline (platform: 60s). |
| `TIMESTAMP_SKEW_MS` | `300000` | Allowed future skew for `issued_at`. |
| `GATEKEEPER_VK_HASH` | `0x6b79c6…d77b0` | Registered mainnet vkHash. |
| `CIRCUIT_WASM_PATH` | `circuits/gatekeeper.wasm` | |
| `CIRCUIT_ZKEY_PATH` | `circuits/gatekeeper_final.zkey` | |
| `VERIFICATION_KEY_PATH` | `circuits/verification_key.json` | |
| `KURIER_ENABLED` | `false` | Set `true` in production. |
| `KURIER_API_KEY` | — | Required when `KURIER_ENABLED=true`. |
| `KURIER_API_URL` | `https://api.kurier.xyz/api/v1` | Testnet: `https://api-testnet.kurier.xyz/api/v1` |
| `KURIER_POLL_INTERVAL_MS` | `5000` | |
| `KURIER_POLL_TIMEOUT_MS` | `30000` | Must stay below `REQUEST_TIMEOUT_MS`. |
| `SEEN_STORE_PATH` | `data/seen.json` | Proof-tx replay store (persisted JSON). |

Never commit `.env` (it is gitignored). Never paste a private key, seed
phrase, or API key into a chat or a prompt.

## Protocol (from https://agentgames.zkverify.io/build)

Task envelope (`POST /agent`, `type: agent-games.proof-gatekeeper.v1`):

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_8d31_...",
  "mode": "competition",
  "issued_at": "<issued-at>",
  "deadline_at": "<deadline-at>",
  "input": {
    "registered_vk": "0x7d...91", "proof_vk": "0x13...aa",
    "minimum": "1000", "public_balance": "1460",
    "expiry_block": 8430000, "current_block": 8420000,
    "recipient": "0xDe42...9f01", "condition_recipient": "0xDe42...9f01",
    "amount": "500", "max_transfer": "1000", "proof_tx": "0xa8...2c"
  }
}
```

Response (signed with `x-agent-games-signature` over the raw body):

```json
{ "decision": "REJECT", "reason_code": "VK_SUBSTITUTION",
  "proof": { "pi_a": [...], "pi_b": [...], "pi_c": [...],
             "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["...", "..."],
  "proof_tx": "0xa8...2c", "proofReference": "<kurier job id, when available>" }
```

Preflight — the platform sends `{ "type": "agent-games.preflight.v1",
"agent_id": "agt_...", "issued_at": "...", "nonce": "abc123" }` (signed);
the agent replies `{ "ok": true, "protocolVersion": "v1" }`, signed.

### Circuit inputs (validated against the official artifacts)

The gatekeeper circuit (Groth16/BN128, Circom 2.2.3) has 13 inputs and
13 public signals. The mapping was validated by generating proofs that
pass `snarkjs groth16 verify` against the exported verification key:

| Signal | Value |
|---|---|
| `taskId` | `keccak256(utf8(task_id)) mod p` |
| `minimum`, `publicBalance`, `expiryBlock`, `currentBlock`, `amount`, `maxTransfer` | decimal strings from the task |
| `recipient`, `conditionRecipient` | `BigInt(address)` as decimal |
| `registeredVkHash`, `proofVkHash` | `BigInt(hex) mod p` as decimal |
| `salt` | fresh random 32 bytes mod p (private, per task) |
| `decision` | `"1"` APPROVE, `"0"` REJECT |

`p` is the BN128 scalar field prime
(`21888242871839275222246405745257275088548364400416034343698204186575808495617`).
Public signals are returned exactly as snarkjs returns them (never
reordered): `[0]` is the `Poseidon(salt, taskId)` binding commitment, the
rest are the public fields in circuit order. The circuit enforces
`decision == computed verdict` — approve iff every check passes — so a
proof for a wrong decision simply cannot be generated.

### Kurier

Submit: `POST {apiUrl}/submit-proof/{apiKey}` with
`{ proofType: "groth16", vkRegistered: true, proofOptions: { library:
"snarkjs", curve: "bn128" }, proofData: { proof, publicSignals, vk } }`.
Poll: `GET {apiUrl}/job-status/{apiKey}/{jobId}` until `Finalized`
(per the zkVerify docs at
https://docs.zkverify.io/overview/getting-started/kurier — the /build page
does not print the poll endpoint, so the poll URL is configurable via
`KURIER_API_URL`). The gatekeeper vk is already registered on mainnet, so
no `register-vk` call is made (`vkRegistered: true`). Kurier is a
confirmation/audit step: if it is disabled, slow, or fails, the decision +
proof are still returned and the outcome is logged. The Kurier job id is
returned as `proofReference` when available.

### PROOF_REUSED and the missing-proof case

`PROOF_REUSED` is an off-chain-only check (the circuit has no reuse input):
a replayed task passes all five on-chain checks, so the circuit's verdict
is APPROVE and it cannot produce a REJECT proof for it. The agent therefore
returns `REJECT / PROOF_REUSED` with **no proof** — the honest fail-closed
answer (correct decision +12, missing proof −2) rather than a fabricated
proof whose public signals would lie about the task. The same applies to
`PROOF_FAILED` (proof generation threw) and `TIMEOUT` (deadline exceeded):
REJECT with no proof. Every other decision always carries a proof.

## Tests

`npm test` builds the project, starts the compiled server on a test port
with a test HMAC secret and an isolated seen-store, and replays envelopes
over real HTTP. It covers: preflight (valid + bad signature), the
VK_SUBSTITUTION trap from /build, a fully valid task, and one of each
THRESHOLD_MISMATCH, EXPIRED, RECIPIENT_MISMATCH, AMOUNT_OVERFLOW,
PROOF_REUSED (replay), plus unknown-type (400) and missing-signature (401).
Every decision test asserts the decision, the reason code, a valid response
HMAC, and that the returned proof passes `snarkjs groth16 verify` (except
PROOF_REUSED, which asserts the documented no-proof case).

On this VM proof generation takes ~0.4–1.2s per task; the harness runs in
~10s. On a production host it is faster.

## Deploy

The service is a plain Node.js HTTP server (stdlib only, no framework) and
runs anywhere Node 20+ runs. A `Dockerfile` is included.

- **Railway / Render / Fly.io:** deploy from this repo (or the Docker
  image); set `AGENT_GAMES_HMAC_SECRET` and `KURIER_API_KEY` in the
  platform's secret store (never in the repo); set `KURIER_ENABLED=true`.
  The `data/` directory holds the replay store — on ephemeral filesystems
  attach a persistent volume, or the seen-set resets on redeploy (a replay
  could then slip through once per redeploy; the in-memory set still
  protects the running process).
- **Vercel:** serverless functions have a 60s limit and cold starts that
  can exceed the proving time; prefer a long-running host (Railway/Render/
  Fly) for this service. If you must use Vercel, keep the function warm.
- **Any VPS:** `npm ci --omit=dev && npm run build`, then run
  `node dist/src/index.js` behind a reverse proxy with TLS (the platform
  requires a public HTTPS endpoint). Use `systemd` or `pm2` to keep it up.

## Project layout

```
gatekeeper-agent/
  src/
    index.ts       entrypoint (config load, artifact validation, listen)
    server.ts      HTTP server, raw-body HMAC, routing, deadline, signing
    hmac.ts        HMAC-SHA256 sign/verify (timing-safe)
    decision.ts    deterministic checks + reason codes (no LLM)
    prover.ts      snarkjs fullProve + the 13-signal input mapping
    kurier.ts      Kurier submit + poll until Finalized
    seenStore.ts   proof_tx replay store (memory + disk JSON)
    config.ts      env loading + validation (refuses placeholder secrets)
    types.ts       envelope / response types
    snarkjs.d.ts   minimal snarkjs type declarations
  test/
    harness.ts     integration harness (spawns the server, replays envelopes)
    fixtures.ts    sample envelopes incl. the /build VK_SUBSTITUTION trap
  circuits/
    gatekeeper.wasm, gatekeeper_final.zkey, verification_key.json
  scratch/         exploratory scripts (not part of the service)
  .env.example, .gitignore, Dockerfile, README.md
```

## Security notes

- Secrets come only from the environment. `.env` is gitignored; the repo
  ships only `.env.example` with blank values.
- The HMAC secret is the platform-generated value from Rotate Secret —
  never a local placeholder. The server refuses to start without it.
- Fail closed: timeout, error, or uncertainty is always a REJECT.
- No language model is involved in any decision.
- Responses are always signed; error responses carry a generic code and
  never leak internals. Secrets are never logged.
