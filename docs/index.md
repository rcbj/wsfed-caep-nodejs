---
title: wsfed-caep-nodejs
---

# wsfed-caep-nodejs

A **WS-Federation relying party** for **server-side** Node.js applications: the traditional web application that renders its pages on the server and keeps its session there. It covers:

- **The passive requestor profile** of WS-Federation 1.2: `wsignin1.0` (with `wfresh`, `wauth`, `whr`), the response POSTed to the reply URL, `wsignout1.0` and `wsignoutcleanup1.0`.
- **SAML 2.0 assertions**, asked for with a `wreq` RequestSecurityToken, in either WS-Trust shape (February 2005, or 1.3 in a collection). A SAML 1.1 token is refused.
- **Strict validation**: the assertion's signature always required, verified only against the identity provider's metadata certificates and read from what was signed (no signature wrapping); audience, recipient, time window, `wctx` correlation, and each assertion accepted once.
- **Encryption**: `EncryptedAssertion`, AD FS's bare `EncryptedData`, `EncryptedID` and `EncryptedAttribute` decrypted with `node:crypto` (AES-GCM/CBC, RSA-OAEP; PKCS#1 v1.5 refused).
- **Federation metadata both ways**: this relying party's written from its configuration, the identity provider's read from a file or a URL.
- **CAEP and RISC**: an OpenID Shared Signals receiver that ends the application's sessions when the identity provider revokes a session or disables an account, whether or not the browser is open. `"signals": false` turns this off. The default is on. Sign-in is unchanged. The relying party does not start a receiver; the application, and the demo, should not start one when the flag is false.

It is TypeScript and works from JavaScript, needs no web framework, and depends on [`xml-crypto`](https://github.com/node-saml/xml-crypto) and [`@xmldom/xmldom`](https://github.com/xmldom/xmldom) only. It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/ws-federation.html)'s WS-Federation identity provider.

## Install

```sh
npm install wsfed-caep-nodejs
```

## Plain http is for loopback only

The library fetches the identity provider's federation metadata (when `idpMetadata` is a URL) and calls the Shared Signals transmitter (configuration, JWKS, stream and poll). Each of these uses https. A plain `http://` URL is refused before any connection, with a `WsFedError` of that fetch's code (`metadata`, `ssf`) naming only the scheme and host, unless the host is loopback: `127.0.0.0/8`, `::1` or `localhost`. A URL with userinfo is never treated as loopback, and a URL with whitespace or a control character is refused. There is no setting to allow it. Your own realm and reply URL may be http; they are never fetched.

## Where to read

- **[Server-side guide](guide.md):** configuration, registration, the login route, the reply URL, sign-out and the session, step by step.
- **[Handling CAEP and RISC events](signals.md):** every CAEP and RISC event type, what it carries, what the receiver does by default, and a handler for each.
- **[Configuration and API reference](reference.md):** every setting, the protocol, what is checked, encryption, errors and the API.
- **[TypeScript API](api/)** (TypeDoc), generated from the source.
- **[Setting up iya-sts](configure.md):** registering the relying party, and reading iya-sts's federation metadata into the library.
- **[Running the demo](demo.md):** a complete application in one container.
- **[Development and releases](development.md):** tests, CI, branches and versions.

## Quick look

```ts
import { RelyingParty } from 'wsfed-caep-nodejs';

const rp = await RelyingParty.fromFile('wsfed.json');

// /login
const request = rp.login({ relayState: '/' });       // keep request.id with the browser
// redirect to request.url

// POST /wsfed (the reply URL)
const who = await rp.handleReply({ method, url, body }, { requestId });
console.log(who.nameId, who.attributes, who.sessionIndex);
```

From JavaScript: `const { RelyingParty } = require('wsfed-caep-nodejs')`, or the same `import`.

The configuration is three lines:

```json
{
  "realm": "https://app.example.com/",
  "replyUrl": "https://app.example.com/wsfed",
  "idpMetadata": "https://idp.example.com/FederationMetadata/2007-06/FederationMetadata.xml"
}
```
