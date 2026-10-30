---
title: Development and releases
---

# Development and releases

## Tests

```sh
npm install
npm test
npm run build
```

The library's tests run with `node:test` on the TypeScript sources directly, against a stub WS-Federation identity provider (`packages/wsfed-caep-nodejs/test/stub-idp.ts`) that publishes federation metadata, writes and signs SAML 2.0 assertions with its own key, encrypts them, and wraps them in WS-Trust responses. They cover:

- the configuration, the IdP's federation metadata (the STS role found by its resolved `xsi:type`, its passive endpoint, token types and keys), and this relying party's metadata;
- the `wsignin1.0` request: realm, reply URL, `wctx`, the `wreq` asking for SAML 2.0, `wfresh`, `wauth`, `whr`; and `wsignout1.0`;
- the response in both WS-Trust shapes: an unsigned assertion, an altered one, another key, four signature-wrapping attacks (one through `wsu:Id`), audience, recipient, issuer, expiry, `AppliesTo`, the response's `Lifetime`, an assertion answering a SAML request, a SAML 1.1 token, the `wctx` correlation, unsolicited, replay, a DOCTYPE;
- encryption: AES-GCM and AES-CBC, RSA-OAEP with SHA-1 and SHA-256, `EncryptedAssertion` and a bare `EncryptedData`, an altered ciphertext, `EncryptedAttribute`, no key, and `wantAssertionsEncrypted`;
- the reply URL: a GET, a wrong `wa`, `wresultptr`, `wsignoutcleanup1.0`;
- the Shared Signals receiver against a stub transmitter;
- **from plain JavaScript**: the example application `examples/node-http.mjs` through a whole sign-in, cleanup and sign-out over HTTP;
- the setup script's plan, offline.

`npm run build` compiles `src/*.ts` to `dist/*.js` and `dist/*.d.ts` with TypeScript 7, strict. CI then loads the build with `require()` and with `import`.

Node.js 22.18 or later is required for the TypeScript sources to run as they are; the published package is JavaScript and runs on Node 22.12 or later.

## Continuous integration

| Workflow | Runs on | Does |
|---|---|---|
| `tests.yml` | every push and pull request | `npm test`, the build, the build loaded from CommonJS and ESM, the manifests check, then builds the demo image and checks its pages, headers, metadata, `wsignin1.0` and cleanup |
| `npm-publish.yml` | pushes to `main` and `develop` that change the package | tests, stamps the version, packs and publishes to npm with provenance |
| `pages.yml` | pushes to `main` that change the docs or the source | builds this site and the TypeDoc reference |

## Branches

- **`develop`** is where work comes together: branch from it and merge back into it.
- **`main`** is what is released.

## Versions and releases

`M.N` is in the `VERSION` file; the patch number is worked out at build time from what is on npm (`scripts/version.mjs`). `main` publishes `M.N.P` under `latest`; `develop` publishes `M.N.P-next.R` under `next`. After bumping `VERSION`, run `npm run version:sync`.

## One-time setup on GitHub and npm

**GitHub Pages** (`pages.yml`). Pages must exist and build from GitHub Actions:

```sh
gh api -X POST repos/rcbj/wsfed-caep-nodejs/pages -f build_type=workflow
```

or **Settings → Pages → Source: GitHub Actions**. The site is then published at <https://rcbj.github.io/wsfed-caep-nodejs/>.

**npm** (`npm-publish.yml`). The package is published as [`wsfed-caep-nodejs`](https://www.npmjs.com/package/wsfed-caep-nodejs), with provenance.

1. Create the repository environment **`npm`** (**Settings → Environments**).
2. For the **first** publish, add the repository secret **`NPM_TOKEN`**: an npm granular access token with publish rights.
3. After the first publish, configure **trusted publishing** on npmjs.com: repository `rcbj/wsfed-caep-nodejs`, workflow `npm-publish.yml`, environment `npm`. Then delete `NPM_TOKEN`.
