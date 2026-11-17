/**
 * Proof-reference replay store (PROOF_REUSED check).
 *
 * A proof_tx must never be accepted twice for the same mode
 * ("competition" vs "practice"). Keys are `${mode}:${proof_tx}`.
 *
 * Kept in memory for speed and persisted to a JSON file on disk so a
 * restart does not forget already-seen references. Writes are atomic
 * (temp file + rename) and debounced to one flush per event loop turn.
 * A missing or corrupt store file starts empty (logged) — the in-memory
 * set still protects the current process.
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export class SeenStore {
  private readonly seen = new Set<string>();
  private readonly path: string;
  private flushScheduled = false;

  constructor(path: string) {
    this.path = path;
    try {
      const raw = readFileSync(path, "utf8");
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const entry of parsed) {
          if (typeof entry === "string") this.seen.add(entry);
        }
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code !== "ENOENT") {
        console.warn(`[seen-store] could not load ${path} (starting empty): ${(err as Error).message}`);
      }
    }
  }

  private key(mode: string, proofTx: string): string {
    return `${mode}:${proofTx.trim()}`;
  }

  isSeen(mode: string, proofTx: string): boolean {
    return this.seen.has(this.key(mode, proofTx));
  }

  /** Record a reference as seen (after a decision is made) and persist. */
  markSeen(mode: string, proofTx: string): void {
    this.seen.add(this.key(mode, proofTx));
    this.scheduleFlush();
  }

  get size(): number {
    return this.seen.size;
  }

  private scheduleFlush(): void {
    if (this.flushScheduled) return;
    this.flushScheduled = true;
    setImmediate(() => {
      this.flushScheduled = false;
      this.flush();
    });
  }

  private flush(): void {
    try {
      mkdirSync(dirname(this.path), { recursive: true });
      const tmp = `${this.path}.tmp`;
      writeFileSync(tmp, JSON.stringify([...this.seen].sort(), null, 2), "utf8");
      renameSync(tmp, this.path);
    } catch (err) {
      console.warn(`[seen-store] failed to persist ${this.path}: ${(err as Error).message}`);
    }
  }
}
