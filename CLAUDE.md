# wsfed-caep-nodejs

A WS-Federation 1.2 passive-requestor relying party for a traditional Node.js application, and a CAEP and RISC receiver. It sends the browser with `wsignin1.0`, asks for a SAML 2.0 assertion, validates that assertion strictly, decrypts it when it is encrypted, and handles `wsignout1.0` and `wsignoutcleanup1.0`. It is TypeScript, usable from JavaScript. Runtime dependencies are `xml-crypto` and `@xmldom/xmldom`.

`"signals": false` turns CAEP and RISC off. The default is on, and a configuration that omits `signals` keeps receiving events. Sign-in is unchanged. The relying party does not start a receiver by itself. The demo does not start one when the flag is false, even if `ssf` is set, and does not require transmitter metadata. `scripts/configure-iya-sts.ts` does not register SSF roles then.

It follows the layout of [saml2-sp-nodejs](https://github.com/rcbj/saml2-sp-nodejs), with WS-Federation in place of the SAML 2.0 HTTP bindings. `packages/wsfed-caep-nodejs/examples/node-http.mjs` is a complete relying party in plain JavaScript.

Documentation: <https://rcbj.github.io/wsfed-caep-nodejs/>. The license is the MIT License in `LICENSE`. The Business Source License used by iya-sts does not apply here.

Node.js 22.18 or later. The package engines field says `>=22.18.0`. Continuous integration runs the suite on 22.18.0 and 24.22.1. The published package also loads from `require()` on Node 22.12 or later.

## Layout

| Path | What it is |
|---|---|
| `packages/wsfed-caep-nodejs` | The library published to npm as `wsfed-caep-nodejs`. Source is `src/` (`relying-party.ts`, `token.ts`, `metadata.ts`, `signature.ts`, `encryption.ts`, `x509.ts`, `ssf/`). Tests and the stub identity provider are `test/`. `examples/node-http.mjs` is the plain-JavaScript sample. `npm run build` writes `dist/`. |
| `demo` | The server-rendered demo. `demo/server.ts` and `demo/public/`. Config is `demo/wsfed.json`. |
| `scripts` | `configure-iya-sts.ts` registers the relying party on iya-sts and writes metadata for the realm and reply URL that run registers. It runs with `node` inside the demo image. `live_iya_sts.py` is the host Python live sign-in. `redirects.mjs` rewrites a loopback URL onto `PORT`. `version.mjs` stamps the published version. |
| `docs` | The GitHub Pages site. |
| `tools/apidocs` | TypeDoc. It is outside the npm workspace. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

The root `package.json` is a private workspace. Committed manifests stay at `M.N.0` from the root `VERSION` file.

## Usage

```sh
npm install wsfed-caep-nodejs
```

```ts
import { RelyingParty, WsFedError } from 'wsfed-caep-nodejs';

const rp = await RelyingParty.fromFile('wsfed.json');
const request = rp.login({ relayState: '/' });
// redirect the browser to request.url
const who = await rp.handleReply({ method: req.method, url: req.url, body }, { requestId });
```

Keep `request.id` with the browser until it returns. The package README and `packages/wsfed-caep-nodejs/docs/guide.md` are the reference.

## Tests

```sh
npm ci
npm test
npm run build
npm run version:check
```

`npm test` runs `node:test` on the TypeScript sources in `packages/wsfed-caep-nodejs/test` and on `scripts/*.test.ts`. The library tests use the stub identity provider in `test/stub-idp.ts`. `version:check` fails unless every manifest is `M.N.0`.

`docker build --target test .` runs that same `npm test` in the Node image. The test stage is not a parent of the demo image, so `docker build .` and `docker compose build` do not run it. Do not run node or npm on the host for the suite. `.github/workflows/tests.yml` still runs `npm test` on the runner. That file is separate from the nightly workflow.

`.github/workflows/tests.yml` also checks that the built package loads from ESM and `require()`, syntax-checks `examples/node-http.mjs`, and builds the demo image. That image job publishes host port 3000. Do not run it while a demo is already bound there. The in-process commands above do not need the container.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
npm install
ADMIN_API_CLIENT_SECRET=… WSFED_DEMO_USER_PASSWORD=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in as `wsfed-demo-user`.

A loopback realm and reply URL follow `PORT` in the running server and in `scripts/configure-iya-sts.ts`. The metadata file is built from those rewritten values, not from the on-disk `localhost:3000` file alone. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. A different port is a different realm, so run `configure-iya-sts` again after changing `PORT`. The previous `:3000` registration stays on iya-sts. `pollIntervalMs` is a millisecond pause, not a port.

`GET /live-status` is JSON: `signedIn`, `subject`, `receiver`, and `events` (`type` and `jti`). No tokens. `python3 scripts/live_iya_sts.py` signs the demo in to a fresh iya-sts and checks that JSON. Configure is `node scripts/configure-iya-sts.ts` inside the demo image. Do not run node or npm on the host for it.

iya-sts main sets the assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index finds nobody. The event handler ends this demo's one session, as wsfed-caep-java does in Demo.java. session-revoked leaves `signedIn` false.

`.github/workflows/nightly.yml` runs `docker build --target test .` and then `python3 scripts/live_iya_sts.py` at 06:07 UTC (`7 6 * * *`), and on `workflow_dispatch`. Do not bind host ports 3000 or 8081.

## Releases

`main` publishes `M.N.P` as npm `latest`. `develop` publishes `M.N.P-next.R` as `next`. The patch is chosen at publish time by `scripts/version.mjs` from the versions already on npm. After bumping `VERSION`, run `npm run version:sync`.

`.github/workflows/npm-publish.yml` runs only when the push changes the package directory, `VERSION`, `package-lock.json`, `scripts/version.mjs`, or that workflow. A change that is only this file, the demo, or the docs does not publish. A pull request packs and publishes nothing.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main`, and fast-forward `develop` to that same commit so both branches name one hash.
