# wsfed-caep-nodejs

A **WS-Federation relying party** for server-side Node.js applications, written in TypeScript and usable from JavaScript, and a demo app built on it. It sends the browser to the identity provider with `wsignin1.0`, asking for a **SAML 2.0 assertion**, receives the WS-Trust response at the reply URL, validates the assertion strictly and decrypts it when it is encrypted, and handles `wsignout1.0` and `wsignoutcleanup1.0`. A **CAEP and RISC receiver** (OpenID Shared Signals) ends the application's sessions when the identity provider revokes them. `"signals": false` turns that off. The default is on. Sign-in is unchanged. The relying party does not start a receiver; the demo does not start one when the flag is false. It depends on `xml-crypto` and `@xmldom/xmldom` only.

It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/ws-federation.html)'s WS-Federation identity provider, and follows [`saml2-sp-nodejs`](https://github.com/rcbj/saml2-sp-nodejs)'s layout: the same thing, with WS-Federation in place of the SAML 2.0 HTTP bindings.

**Documentation:** <https://rcbj.github.io/wsfed-caep-nodejs/>

| Path | |
|---|---|
| [`packages/wsfed-caep-nodejs`](packages/wsfed-caep-nodejs) | The library, published to npm as [`wsfed-caep-nodejs`](https://www.npmjs.com/package/wsfed-caep-nodejs). [`examples/node-http.mjs`](packages/wsfed-caep-nodejs/examples/node-http.mjs) is a complete relying party in plain JavaScript. |
| [`demo`](demo) | A traditional server-rendered web application, run in one container. |
| [`scripts/configure-iya-sts.ts`](scripts/configure-iya-sts.ts) | Registers the demo on a running iya-sts as a WS-Federation relying party, and reads iya-sts's federation metadata back. |

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

Open <http://localhost:3000> and sign in as `wsfed-demo-user`. See [Running the demo](docs/demo.md) and [Setting up iya-sts](docs/configure.md).

## Develop

```sh
npm install
npm test
npm run build
```

Branch from `develop`. See [Development and releases](docs/development.md).

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
