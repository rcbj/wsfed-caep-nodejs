# wsfed-caep-nodejs

A **WS-Federation relying party** for server-side Node.js applications: the passive requestor profile of WS-Federation 1.2 (`wsignin1.0`, `wsignout1.0`, `wsignoutcleanup1.0`), with the token a **SAML 2.0 assertion**, validated strictly and decrypted when it is encrypted, and a **CAEP and RISC receiver** that ends the application's sessions when the identity provider says so. Written in TypeScript, usable from JavaScript (ESM, or `require()` on Node 22.12+). Two runtime dependencies: [`xml-crypto`](https://github.com/node-saml/xml-crypto) and [`@xmldom/xmldom`](https://github.com/xmldom/xmldom). Everything else is `node:crypto` and `node:https`.

**Documentation:** <https://rcbj.github.io/wsfed-caep-nodejs/> (guide, Shared Signals handlers, API reference)

```sh
npm install wsfed-caep-nodejs
```

It speaks no web framework. The calls take and return plain values, so it fits Express, Fastify, Koa or `node:http` alike. See the [server-side guide](docs/guide.md) for a walkthrough, and [`examples/node-http.mjs`](examples/node-http.mjs) for a complete application in plain JavaScript.

## Quick look

```ts
import { RelyingParty, WsFedError } from 'wsfed-caep-nodejs';

const rp = await RelyingParty.fromFile('wsfed.json');

// GET /login: to the identity provider with wa=wsignin1.0. Keep request.id with the browser until it comes back.
const request = rp.login({ relayState: '/' });
// redirect to request.url

// POST /wsfed (the reply URL): the identity provider's form posts wa, wresult and wctx here.
try {
  const who = await rp.handleReply({ method: req.method, url: req.url, body }, { requestId });
  // who.nameId, who.attributes, who.sessionIndex, who.relayState, ...
} catch (err) {
  if (err instanceof WsFedError) console.warn(err.code, err.message);
}

// GET /wsfed?wa=wsignoutcleanup1.0: the identity provider signing the person out of every relying party.
if (rp.isSignOutCleanup({ method: req.method, url: req.url })) { /* end the session; answer with an image */ }

// GET /FederationMetadata/2007-06/FederationMetadata.xml: this relying party's metadata.
res.end(rp.metadata());
```

From JavaScript it is the same without the types:

```js
import { RelyingParty } from 'wsfed-caep-nodejs';           // ESM
const { RelyingParty } = require('wsfed-caep-nodejs');       // CommonJS, Node 22.12+
```

## The configuration

```json
{
  "realm": "https://app.example.com/",
  "replyUrl": "https://app.example.com/wsfed",
  "idpMetadata": "https://idp.example.com/FederationMetadata/2007-06/FederationMetadata.xml"
}
```

| Setting | Default | |
|---|---|---|
| `realm` | required | This relying party's realm: the `wtrealm` it sends, the audience every assertion must name, and its metadata's entityID. |
| `replyUrl` | required | The reply URL (`wreply`): where the identity provider posts the token, and sends `wsignoutcleanup1.0`. |
| `idpMetadata` | required | The identity provider's federation metadata: a file path, an `https` URL, or the XML. Its entityID, passive requestor endpoint, token types and signing certificates are read from it. |
| `privateKey`, `certificate` | — | An RSA key and its certificate (file paths relative to the configuration file, or the PEM). Encrypted assertions are decrypted with it, the metadata publishes it as the encryption key, and the Shared Signals receiver can present it as a TLS client certificate. WS-Federation itself signs nothing. |
| `wantAssertionsEncrypted` | `false` | Refuse an assertion that is not encrypted. Needs the key pair. |
| `requestTokenType` | `true` | Ask for a SAML 2.0 assertion with a `wreq` RequestSecurityToken naming its TokenType. Turn off only for an identity provider that refuses `wreq` and issues SAML 2.0 to this realm by itself. |
| `idpCa` | — | PEM certificate(s) to trust for TLS to the identity provider (the metadata URL), in addition to node's own store. |
| `idpEntityId` | — | For metadata that is an aggregate: which identity provider. |
| `clockSkewSeconds` | `60` | How far the two clocks may disagree. |
| `allowUnsolicited` | `false` | Accept a sign-in response no request asked for (identity-provider-initiated sign-in). |

`RelyingParty.create(config, { baseDir })` takes the same members as an object.

## The protocol

| Message | | This library |
|---|---|---|
| `wsignin1.0` request | The browser is redirected to the identity provider's PassiveRequestorEndpoint with `wtrealm`, `wreply`, `wctx`, `wct`, and `wreq` asking for `urn:oasis:names:tc:SAML:2.0:assertion`. Optionally `wfresh` (`forceAuthn` is `wfresh=0`), `wauth` (`authenticationMethod`), `whr`. | `rp.login()` |
| `wsignin1.0` response | The identity provider's page POSTs `wa`, `wresult` (a WS-Trust RequestSecurityTokenResponse around the assertion) and `wctx` to the reply URL. | `rp.handleReply()` |
| `wsignout1.0` | The browser is sent to the identity provider to end its session there. | `rp.logout({ reply })` |
| `wsignoutcleanup1.0` | The identity provider loads the reply URL as an image, so the relying party ends its session. | `rp.isSignOutCleanup()` |

**`wauth`.** Pass it as `authenticationMethod` to `login()`. The value is one URI. Two factors is `http://schemas.microsoft.com/claims/multipleauthn`:

```ts
rp.login({
  relayState: '/',
  authenticationMethod: 'http://schemas.microsoft.com/claims/multipleauthn',
});
```

The [guide](docs/guide.md#asking-for-a-sign-in-method-wauth) walks through the call. iya-sts treats a demand the session does not already meet as a step-up, and the URIs it accepts are on its [WS-Federation page](https://rcbj.github.io/iya-sts/configure-ws-federation.html#wauth-demand-a-sign-in-method).

The response is read in either WS-Trust shape: a February 2005 `RequestSecurityTokenResponse` (what AD FS and iya-sts send by default), or a WS-Trust 1.3 `RequestSecurityTokenResponseCollection` holding one. `wresultptr` is refused: a reference is never dereferenced.

**`wctx` correlates the response with the request.** A WS-Federation sign-in request is not signed, and the assertion answers no request id. The one value the identity provider returns unchanged is `wctx`, so `login()` puts the request's id there (`id=<id>&ru=<relayState>`, the shape WIF uses) and `handleReply()` requires it to be one this browser has outstanding. That stops a response from being pushed into a browser that never asked for one (login CSRF). It is not what makes the sign-in genuine: the assertion's signature, audience and lifetime are.

## What it checks

Every sign-in response:

- **No DOCTYPE**, and no two elements sharing an ID (by local name, so `wsu:Id` counts), which is how a signature is made to point at the wrong element.
- **The response**: `wa=wsignin1.0`, POSTed, with `wresult`; exactly one RequestSecurityTokenResponse, its `AppliesTo` (when present) this realm, its `Lifetime` not passed, its `TokenType` (when present) SAML 2.0, and exactly one token in its `RequestedSecurityToken`.
- **A SAML 2.0 assertion.** A SAML 1.1 assertion, the default token many identity providers issue to a WS-Federation relying party, is refused with a message saying how to ask for SAML 2.0.
- **The assertion's signature, always required**, against the identity provider's own certificates from its metadata, never against a certificate the message carries. In WS-Federation the response around the assertion is not signed, so the assertion's signature is the only one. RSA-SHA256/384/512 only; SHA-1 is refused. It must be an enveloped signature of the assertion: one reference, to its ID, with only the enveloped and canonicalization transforms.
- **What was signed is what is read.** Once the signature verifies, the assertion is parsed from the XML that was signed, so a forged element beside it is not seen.
- **The assertion**: the identity provider as Issuer; a bearer `SubjectConfirmation` that has not expired, has no `NotBefore`, and has no `InResponseTo` (there was no AuthnRequest; one that answers a SAML request belongs to a SAML Web SSO exchange, not to this one) and whose `Recipient`, if the identity provider sets one, is the reply URL; `Conditions` in their time window; this realm in every `AudienceRestriction`; an `AuthnStatement`, its `SessionNotOnOrAfter` not passed.
- **Once only**: the assertion's ID is remembered until it could no longer be presented. The default `MemoryReplayCache` is one process's. Give `RelyingParty` a shared `replayCache` when the application runs several.

## Encryption

An `EncryptedAssertion`, or a bare `xenc:EncryptedData` in the `RequestedSecurityToken` (how AD FS encrypts a WS-Federation token), is decrypted with `node:crypto`, and so are `EncryptedID` and `EncryptedAttribute`: AES-GCM or AES-CBC content, the key wrapped with RSA-OAEP (`rsa-oaep-mgf1p`, or XML Encryption 1.1 `rsa-oaep` with one hash for digest and MGF1). **RSA PKCS#1 v1.5 key transport is refused.** The metadata publishes the encryption key and the algorithms accepted. The assertion inside must still be signed.

## Shared Signals: CAEP and RISC

`SignalsReceiver` makes the application a Shared Signals receiver (OpenID SSF 1.0, poll delivery per RFC 8936). It has **one stream** at the identity provider, carrying CAEP session events and RISC account events about **every person** who uses the application. Each event is turned into the application's own sessions to end. WS-Federation's own sign-out reaches the relying party only through the browser (`wsignoutcleanup1.0`, an image load a browser may block); a CAEP event reaches it whether or not the browser is open.

```ts
import { EVENT, RelyingParty, SignalsReceiver } from 'wsfed-caep-nodejs';

const rp = await RelyingParty.fromFile('wsfed.json');
const signals = new SignalsReceiver({
  transmitter: 'https://idp.example.com',
  // Mutual TLS with the RP's own key pair: no token, no secret.
  tls: { ca: rp.config.idpCa, cert: rp.config.certificate!.toString(),
         key: rp.config.privateKey!.export({ type: 'pkcs8', format: 'pem' }) as string },
  onEndSessions: (localIds, event) => { for (const id of localIds) sessionStore.destroy(id); },
});
signals.on(EVENT.credentialChange, (event) => console.log('credential changed:', event.payload.credential_type));
signals.on('*', (event) => console.log(event.type, event.subject));
await signals.start();

// at the reply URL, after the session is created:
await signals.track(session.id, who);
// at sign-out:
await signals.untrack(session.id);
```

- **One stream, found or created.** `start()` reads `/.well-known/ssf-configuration`. It reuses the application's poll stream (`GET` on the configuration endpoint lists the caller's streams) or creates one, then polls.
- **Every SET is verified before anything acts on it**: the signature against the transmitter's JWKS (RS, PS, ES, EdDSA; the key chosen by `kid`, never from the token), `iss`, `aud` (the stream's), `typ` and `jti`. A SET is acknowledged only once handled. One it refuses is reported in `setErrs` and changes nothing.
- **Matching events to sessions.** `track()` records three things from the sign-in:
  - the person's subject, read from the claim `subjectAttribute` names, which defaults to the `nameidentifier` claim iya-sts and AD FS issue (`urn:uuid:…` on iya-sts);
  - their email address (the `emailaddress` claim, among others);
  - the IdP session, the assertion's `SessionIndex`, which is the session id a CAEP event names.

  A `session-revoked` naming an IdP session ends only the local sessions started from it. An account event (`account-disabled`, `account-purged`, `credential-compromise`, `sessions-revoked`) ends all of the person's local sessions. `endOn` changes which types end sessions; every event also goes to the `on(type)` handlers.
- **Handlers, one per event type.** `on(EVENT.x, handler)` for any of CAEP's eight and RISC's fourteen types (`EVENT`, `CAEP_EVENTS`, `RISC_EVENTS`), or `'*'` for all. Handlers run after the SET is verified and before it is acknowledged. One that throws is logged, and the SET is still acknowledged. **[Handling CAEP and RISC events](docs/signals.md)** lists every type, its members, its default and a handler for each.
- **Several processes.** The default `MemorySessionIndex` is one process's memory. Give every process the same `sessionIndex` (a table, Redis), and run the receiver in one of them, so an event ends sessions wherever they were created.
- **Authentication.** Use `tls.cert`/`tls.key` (mutual TLS), or `headers()` to supply an `authorization` header for a transmitter that wants a token.

## Errors

Every failure is a `WsFedError` with a `code`: `config`, `metadata`, `message` (not a sign-in response this relying party reads), `xml`, `signature`, `validation`, `replay`, `decryption` or `ssf` (the Shared Signals transmitter or stream). Log the message; tell the person only that sign-in failed.

## The command line

```sh
npx wsfed-caep-nodejs generate-keys --config wsfed.json   # a new RSA key and a self-signed certificate
npx wsfed-caep-nodejs metadata --config wsfed.json --out rp-metadata.xml
```

`generate-keys` writes where the configuration's `privateKey` and `certificate` point (or `--key`/`--cert`), refuses to replace them without `--force`, and takes `--cn`, `--days` (1095) and `--bits` (3072).

## API

| | |
|---|---|
| `RelyingParty.fromFile(path, overrides?, options?)` | Read a JSON configuration (paths relative to it) and load the IdP metadata. |
| `RelyingParty.create(config, { baseDir?, replayCache? })` | The same from an object. |
| `rp.login({ relayState?, forceAuthn?, freshness?, authenticationMethod?, homeRealm?, params? })` | A `wsignin1.0` request: `{ id, url, wctx }`. Redirect to `url`; keep `id`. `params` adds query parameters of the identity provider's own (e.g. `login_hint`). |
| `rp.handleReply({ method, url, body? }, { requestId? })` | Validate the sign-in response; resolves to a `WsFedLogin`. `body` is the raw form text or a parsed object. |
| `rp.isSignOutCleanup({ method, url, body? })` | Whether the request is `wsignoutcleanup1.0` (or `wsignout1.0`). |
| `rp.logout({ reply? })` | The `wsignout1.0` URL. |
| `rp.metadata()` | This relying party's federation metadata. |
| `rp.refreshMetadata()` | Read the IdP metadata again (a key rollover). |
| `rp.idp`, `rp.config` | What was read. |
| `MemoryReplayCache`, `ReplayCache` | The default replay cache, and the interface for a shared one (`checkAndRecord(id, expiresAt)`). |
| `WsFedError` | Every failure. |

`WsFedLogin`: `nameId`, `nameIdFormat`, `nameQualifier`, `spNameQualifier`, `sessionIndex`, `sessionNotOnOrAfter`, `authnInstant`, `authnContextClassRef`, `attributes` (claim URI → values), `attributeFriendlyNames`, `issuer`, `realm`, `requestId`, `relayState`, `trustVersion` (`'2005/02'` or `'1.3'`), `encrypted`, `assertionId`, `notOnOrAfter`.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
