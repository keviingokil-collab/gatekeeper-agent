# Proof Gatekeeper agent (zkVerify Agent Games)
FROM node:22-alpine

WORKDIR /app

# Install dependencies first (better layer caching).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy source, circuits, and build config; compile TypeScript.
COPY tsconfig.json ./
COPY src ./src
COPY circuits ./circuits
RUN npm install --no-save typescript@5 && npx tsc -p tsconfig.json && npm prune --omit=dev

# Non-root user.
RUN addgroup -S agent && adduser -S agent -G agent && mkdir -p data && chown -R agent:agent /app
USER agent

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

# AGENT_GAMES_HMAC_SECRET (and KURIER_API_KEY) must be injected at runtime
# via the platform's secret store — never baked into the image.
CMD ["node", "dist/src/index.js"]
