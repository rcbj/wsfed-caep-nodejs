# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# `docker build --target test` runs the suite in the Node image. That stage is not a parent of the
# demo image, so `docker build .` and `docker compose build` do not run it.
# The demo image compiles the library, then keeps the compiled library, its two runtime dependencies,
# the demo (Node runs server.ts as it is), and the sources `node scripts/configure-iya-sts.ts` needs.
# The key pair, the metadata and the IdP's TLS root are NOT in the image. Compose mounts them at
# /app/demo/generated. The live sign-in mounts a work directory and runs that configure script here.
# 24.22.1: the 21 October 2026 security release, which fixes HTTP2Shell / Node2Shell (CVE-2026-111497).
FROM node:24.22.1-alpine AS test
WORKDIR /src
COPY package.json package-lock.json VERSION ./
COPY packages/wsfed-caep-nodejs/package.json packages/wsfed-caep-nodejs/
COPY demo/package.json demo/
RUN npm ci --workspaces --include-workspace-root --ignore-scripts
COPY packages/wsfed-caep-nodejs packages/wsfed-caep-nodejs
COPY scripts scripts
COPY demo/wsfed.json demo/
RUN npm test

FROM node:24.22.1-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages/wsfed-caep-nodejs/package.json packages/wsfed-caep-nodejs/
COPY demo/package.json demo/
RUN npm ci --workspaces --include-workspace-root --ignore-scripts
COPY packages/wsfed-caep-nodejs/tsconfig.json packages/wsfed-caep-nodejs/
COPY packages/wsfed-caep-nodejs/src packages/wsfed-caep-nodejs/src
RUN npm run build -w packages/wsfed-caep-nodejs

FROM node:24.22.1-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/wsfed-caep-nodejs/package.json packages/wsfed-caep-nodejs/
COPY demo/package.json demo/
RUN npm ci --omit=dev --workspaces --include-workspace-root --ignore-scripts && npm cache clean --force
COPY --from=build /src/packages/wsfed-caep-nodejs/dist packages/wsfed-caep-nodejs/dist
COPY demo/server.ts demo/wsfed.json demo/
COPY demo/public demo/public
COPY scripts/redirects.mjs scripts/configure-iya-sts.ts scripts/
COPY packages/wsfed-caep-nodejs/src packages/wsfed-caep-nodejs/src
USER node
EXPOSE 3000
# PORT defaults to 3000 so a run that does not set it (the CI demo job) is still healthy.
# Compose passes PORT and overrides this. The shell form expands it; EXPOSE does not, so it stays 3000.
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null || exit 1
CMD ["node", "demo/server.ts"]
