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
| `scripts` | `configure-iya-sts.ts`, the install script, registers the relying party on iya-sts, writes the listener CA trust chain to the file `idpCa` names, and writes metadata for the realm and reply URL that run registers. It runs with `node` inside the demo image. `trust-chain.mjs` holds `saveTrustChain()`. `trust-chain.test.ts`: the chain is written whole to `idpCa`'s path, and the library reads metadata through it and still checks the host name. `live_iya_sts.py` is the host Python live sign-in. `redirects.mjs` rewrites a loopback URL onto `PORT`. `version.mjs` stamps the published version. |
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

Open <http://localhost:3000> and sign in as `wsfed-demo-user`. Unless `WSFED_DEMO_USER_PASSWORD` sets its password, iya-sts generates one, and the install script writes it to `demo/generated/wsfed-demo-user.password` (created mode 0600) and prints only that path, never the password.

A loopback realm and reply URL follow `PORT` in the running server and in `scripts/configure-iya-sts.ts`. The metadata file is built from those rewritten values, not from the on-disk `localhost:3000` file alone. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. A different port is a different realm, so run `configure-iya-sts` again after changing `PORT`. The previous `:3000` registration stays on iya-sts. `pollIntervalMs` is a millisecond pause, not a port.

`GET /live-status` is JSON: `signedIn`, `subject`, `receiver`, and `events` (`type` and `jti`). No tokens. `python3 scripts/live_iya_sts.py` signs the demo in to a fresh iya-sts and checks that JSON. `IYA_STS_URL` uses one already running; `IYA_STS_IMAGE` starts a fresh container from that image instead of cloning and building `main`. It copies the checkout to a scratch build context, builds the demo image there, and runs the install script `node scripts/configure-iya-sts.ts` in it, which writes the key pair, the IdP metadata and the `idpCa` chain into the context's `demo/generated`. Then it builds the demo image again, checks it carries that chain (and nothing else from `demo/generated`), and runs it on `LIVE_DEMO_PORT` (default 18651) with host networking and only the key, the certificate and the IdP metadata mounted, one file each. It never rewrites `idpCa` or fetches the CA for the demo. iya-sts is published on `127.0.0.1:LIVE_STS_PORT` (default 18551). Use a fresh iya-sts for every run. Do not run node or npm on the host for it. Its Driver logs no request URL or status: CodeQL treats anything after the password POST as derived from the password. Every `ssl` context it makes has a TLS 1.2 minimum.

iya-sts main sets the assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index finds nobody. The event handler ends this demo's one session, as wsfed-caep-java does in Demo.java. session-revoked leaves `signedIn` false.

`.github/workflows/nightly.yml` runs `docker build --target test .` and then `python3 scripts/live_iya_sts.py` at 06:07 UTC (`7 6 * * *`), and on `workflow_dispatch`. It never binds host port 3000, 8081, or 18481 to 18495.

## The iya-sts trust chain (`idpCa`)

`idpCa` in `demo/wsfed.json` names the iya-sts TLS listener CA trust chain the library trusts when it reads the identity provider's metadata over HTTPS and calls the Shared Signals transmitter. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be the PEM itself. The library trusts every certificate in it, in addition to Node's own store, and still checks the host name against the listener certificate's subjectAltName.

`scripts/configure-iya-sts.ts`, the install script, writes that file on every run. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer (`scripts/trust-chain.mjs`). It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts (a development iya-sts makes a new CA when it restarts). `.dockerignore` admits only that file from `demo/generated`; the key pair and both metadata documents stay out of the image. A build with no chain file yet (a fresh clone, CI's `--target test`) still succeeds; the image then has no `idpCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing path and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both. The container does not refresh the chain at start. `node scripts/trust-chain.mjs --config demo/wsfed.json --idp https://localhost:8081` refreshes the file by hand. Compose mounts `demo/generated` (for the key, the certificate and the IdP metadata), which hides the image's copy behind the host's file.

**Plain http (#18).** `send()` in `packages/wsfed-caep-nodejs/src/http.ts` is the one place every fetch goes through (metadata URL, SSF configuration, JWKS, stream and poll). It refuses a URL with whitespace or a control character, and plain `http://` to a host that is not loopback (`127.0.0.0/8`, `[::1]`, `localhost`, by `isLoopbackHost()` on the WHATWG hostname), before any lookup or connection, keeping the fetch's `WsFedError` code and naming only `http://host[:port]`; userinfo is never loopback. node:http(s) follows no redirect. No opt-out. `test/plain-http.test.ts` covers it; `http://0.0.0.0:<port>` reaches a 127.0.0.1 listener on Linux, so its tripwire listener proves no connection is opened.

## Releases

`main` publishes `M.N.P` as npm `latest`. `develop` publishes `M.N.P-next.R` as `next`. The patch is chosen at publish time by `scripts/version.mjs` from the versions already on npm. After bumping `VERSION`, run `npm run version:sync`.

`.github/workflows/npm-publish.yml` runs only when the push changes the package directory, `VERSION`, `package-lock.json`, `scripts/version.mjs`, or that workflow. A change that is only this file, the demo, or the docs does not publish. A pull request packs and publishes nothing.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main`, and fast-forward `develop` to that same commit so both branches name one hash.
