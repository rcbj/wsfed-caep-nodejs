# wsfed-caep-nodejs

A **WS-Federation relying party** for server-side Node.js applications, written in TypeScript and usable from JavaScript, and a demo app built on it. It sends the browser to the identity provider with `wsignin1.0`, asking for a **SAML 2.0 assertion**, receives the WS-Trust response at the reply URL, validates the assertion strictly and decrypts it when it is encrypted, and handles `wsignout1.0` and `wsignoutcleanup1.0`. A **CAEP and RISC receiver** (OpenID Shared Signals) ends the application's sessions when the identity provider revokes them. `"signals": false` turns that off. The default is on. Sign-in is unchanged. The relying party does not start a receiver; the demo does not start one when the flag is false. It depends on `xml-crypto` and `@xmldom/xmldom` only.

It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/ws-federation.html)'s WS-Federation identity provider, and follows [`saml2-sp-nodejs`](https://github.com/rcbj/saml2-sp-nodejs)'s layout: the same thing, with WS-Federation in place of the SAML 2.0 HTTP bindings.

**Documentation:** <https://rcbj.github.io/wsfed-caep-nodejs/>

| Path | |
|---|---|
| [`packages/wsfed-caep-nodejs`](packages/wsfed-caep-nodejs) | The library, published to npm as [`wsfed-caep-nodejs`](https://www.npmjs.com/package/wsfed-caep-nodejs). [`examples/node-http.mjs`](packages/wsfed-caep-nodejs/examples/node-http.mjs) is a complete relying party in plain JavaScript. |
| [`demo`](demo) | A traditional server-rendered web application, run in one container. |
| [`scripts/configure-iya-sts.ts`](scripts/configure-iya-sts.ts) | The install script. Registers the demo on a running iya-sts as a WS-Federation relying party, writes the iya-sts listener CA trust chain to the file `idpCa` names, and reads iya-sts's federation metadata back. |

## Install

```sh
npm install wsfed-caep-nodejs
```

See the [package README](packages/wsfed-caep-nodejs/README.md) for the reference and the [server-side guide](packages/wsfed-caep-nodejs/docs/guide.md) for a walkthrough.

## Run the demo

```sh
npm install
ADMIN_API_CLIENT_SECRET=… WSFED_DEMO_USER_PASSWORD=… npm run configure-iya-sts   # key pair, metadata, registration on iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in as `wsfed-demo-user`. Unless `WSFED_DEMO_USER_PASSWORD` sets its password, iya-sts generates one, and the install script writes it to `demo/generated/wsfed-demo-user.password` (created mode 0600) and prints only that path, never the password. See [Running the demo](docs/demo.md) and [Setting up iya-sts](docs/configure.md).

## The iya-sts trust chain (`idpCa`)

`idpCa` in `demo/wsfed.json` names the iya-sts TLS listener CA trust chain the library trusts when it reads the identity provider's metadata over HTTPS and calls the Shared Signals transmitter. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be the PEM itself. The library trusts every certificate in it, in addition to Node's own store, and still checks the host name against the listener certificate's subjectAltName.

`scripts/configure-iya-sts.ts`, the install script, writes that file on every run. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer (`scripts/trust-chain.mjs`). When the file already holds a chain, the fetch is verified against it; only when that chain cannot verify the server (no file yet, or a new CA) is the chain taken on first use, after checking that the leaf names the host and is the one the handshake presented, and that each certificate is signed by the next. It prints whether it verified, the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts (a development iya-sts makes a new CA when it restarts). `.dockerignore` admits only that file from `demo/generated`; the key pair and both metadata documents stay out of the image. A build with no chain file yet (a fresh clone, CI's `--target test`) still succeeds; the image then has no `idpCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing path and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both. The container does not refresh the chain at start. `node scripts/trust-chain.mjs --config demo/wsfed.json --idp https://localhost:8081` refreshes the file by hand. Compose mounts `demo/generated` (for the key, the certificate and the IdP metadata), which hides the image's copy behind the host's file.

**Plain http (#18).** Federation metadata from a URL and every Shared Signals transmitter call (configuration, JWKS, stream and poll) use https. A plain `http://` URL is refused before any connection unless its host is loopback (`127.0.0.0/8`, `::1`, `localhost`), because metadata carries the signing keys and Shared Signals carry SETs and the bearer token. A URL with userinfo is never loopback, and a URL with whitespace or a control character is refused. The `WsFedError` keeps the fetch's code (`metadata`, `ssf`) and names the scheme and host only. There is no opt-out. The relying party's own realm and reply URL may stay http; they are never fetched.

## Live sign-in

The unit suite is one image. It does not run as part of `docker build .` or `docker compose build`.

```sh
docker build --target test .
```

`python3 scripts/live_iya_sts.py` is the live half, on the host's Python. It starts a fresh iya-sts in memory mode unless `IYA_STS_URL` is already set (`IYA_STS_IMAGE` names an iya-sts image to start instead of building `main`). It copies this checkout to a scratch build context, builds the demo image there and runs the install script `node scripts/configure-iya-sts.ts` inside it, which writes the key pair, the IdP metadata and the `idpCa` chain into the context's `demo/generated`. Then it builds the demo image again, checks the image carries the chain and nothing else from `demo/generated`, and starts it with only the key, the certificate and the IdP metadata mounted, one file each. It never rewrites `idpCa` or fetches the CA for the demo. Do not run node or npm on the host. `LIVE_STS_PORT` (default 18551) and `LIVE_DEMO_PORT` (default 18651) choose the ports. The script signs in, emits credential-change, then session-revoked, and requires `GET /live-status` to show both. That JSON is `signedIn`, `subject`, `receiver`, and `events` of `type` and `jti`. It has no tokens. session-revoked leaves `signedIn` false.

iya-sts main sets the WS-Federation assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index finds nobody. The demo ends its one session from the event handler, as the Java demo does in `Demo.java`.

It never binds host port 3000, 8081, or 18481 to 18495. [`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) runs the unit image and then the live script at 06:07 UTC (`7 6 * * *`), and on `workflow_dispatch`. Push and pull-request CI stays in `tests.yml`.

## Develop

```sh
npm install
npm test
npm run build
```

Branch from `develop`. See [Development and releases](docs/development.md).

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
