/**
 * Entrypoint: load config (refuses to start without AGENT_GAMES_HMAC_SECRET),
 * validate the circuit artifacts, then serve.
 *
 * No secret is ever printed. Startup logs only non-sensitive facts.
 */

import { loadConfig, validateCircuitArtifacts } from "./config.js";
import { createAgentServer } from "./server.js";
import { SeenStore } from "./seenStore.js";

function main(): void {
  const config = loadConfig();
  validateCircuitArtifacts(config);
  const seen = new SeenStore(config.seenStorePath);
  const server = createAgentServer({ config, seen });

  server.listen(config.port, () => {
    console.log(
      `[agent] listening on :${config.port} ` +
        `(vk ${config.vkHash.slice(0, 10)}…, kurier ${config.kurierEnabled ? "enabled" : "disabled"}, ` +
        `request timeout ${config.requestTimeoutMs}ms, seen refs ${seen.size})`
    );
  });

  const shutdown = (signal: string) => {
    console.log(`[agent] ${signal} — shutting down`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5_000).unref();
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main();
