# Adding WS-Federation sign-in to a server-side web application

This walks through what a traditional, server-rendered application needs: the configuration and metadata, the two routes, the cookie that carries the request id, sign-out, and the session. The [demo](../../../demo/server.ts) is all of it in one file with `node:http`, and [`examples/node-http.mjs`](../examples/node-http.mjs) is the smallest version in plain JavaScript; the same steps in Express are below.

## 1. The configuration, and a key pair if you need one

```json
{
  "realm": "https://app.example.com/",
  "replyUrl": "https://app.example.com/wsfed",
  "idpMetadata": "https://idp.example.com/FederationMetadata/2007-06/FederationMetadata.xml",
  "privateKey": "keys/rp.key",
  "certificate": "keys/rp.crt"
}
```

The realm is how the identity provider knows this application: it is the `wtrealm` sent and the audience every assertion must name. The reply URL is where the token comes back.

A WS-Federation relying party signs nothing, so the key pair is optional. Make one if the identity provider encrypts tokens, or to authenticate the Shared Signals receiver by mutual TLS (step 7):

```sh
npx wsfed-caep-nodejs generate-keys --config wsfed.json
```

Keep the private key out of the image and out of version control: mount it, or read it from your secret store and pass the PEM in `privateKey`.

## 2. Register with the identity provider

The identity provider needs the realm and the reply URL. Product-mode identity providers (iya-sts, AD FS) post a token only to a reply URL registered in advance, matched exactly. Many also read this relying party's federation metadata:

```sh
npx wsfed-caep-nodejs metadata --config wsfed.json --out rp-metadata.xml
```

Save the identity provider's metadata where `idpMetadata` points, or point `idpMetadata` at its URL (`/FederationMetadata/2007-06/FederationMetadata.xml` on AD FS and iya-sts). For iya-sts, [`scripts/configure-iya-sts.ts`](../../../scripts/configure-iya-sts.ts) does both through its management API.

## 3. The login route

```ts
import express from 'express';
import { RelyingParty } from 'wsfed-caep-nodejs';

const rp = await RelyingParty.fromFile('wsfed.json');
const app = express();

app.get('/login', (req, res) => {
  const request = rp.login({ relayState: '/' });
  // The request id goes with THIS browser, so the response can be matched to it. SameSite=None: the
  // identity provider posts the response from its own site, a cross-site POST that drops a Lax cookie.
  res.cookie('wsfed_pending', sign(request.id), {
    httpOnly: true, secure: true, sameSite: 'none', path: '/wsfed', maxAge: 600_000,
  });
  res.redirect(request.url);
});
```

`sign()` is your application's cookie signing (`cookie-parser` with a secret, or an HMAC). The id is not a secret, but a cookie the browser could replace would let it choose which request a response answers.

`login()` takes the protocol's options: `forceAuthn` (`wfresh=0`, authenticate again even with a session), `freshness` (`wfresh` in minutes), `authenticationMethod` (`wauth`), and `homeRealm` (`whr`).

### Asking for a sign-in method (`wauth`)

`authenticationMethod` is sent as the `wauth` query parameter: one URI naming the method the identity provider must use. The library does not interpret the URI.

```ts
const request = rp.login({
  relayState: '/',
  authenticationMethod: 'http://schemas.microsoft.com/claims/multipleauthn',
});
```

`http://schemas.microsoft.com/claims/multipleauthn` asks for two factors. On iya-sts a `wauth` the current session does not already meet is a step-up: the person signs in again with that method required, and the assertion reports what happened. iya-sts accepts one URI and refuses a value it does not know. The URIs it honours, and what meets each, are on [Configuring WS-Federation](https://rcbj.github.io/iya-sts/configure-ws-federation.html#wauth-demand-a-sign-in-method).

## 4. The reply URL

```ts
app.post('/wsfed', express.urlencoded({ extended: false, limit: '512kb' }), async (req, res) => {
  try {
    const who = await rp.handleReply(
      { method: req.method, url: req.originalUrl, body: req.body },
      { requestId: unsign(req.cookies.wsfed_pending) },
    );
    res.clearCookie('wsfed_pending', { path: '/wsfed' });
    req.session.regenerate(() => {          // a new session id at sign-in
      req.session.user = { nameId: who.nameId, claims: who.attributes, sessionIndex: who.sessionIndex };
      res.redirect(303, safeLocal(who.relayState) ?? '/');
    });
  } catch (err) {
    console.warn('WS-Federation sign-in refused', err.code, err.message);
    res.status(400).send('Sign-in failed.');
  }
});
```

- **`relayState` came through the browser** in `wctx`. Only follow it to a path on your own site (`safeLocal`), never to an absolute URL.
- **Regenerate the session** at sign-in, and set its lifetime no longer than `who.sessionNotOnOrAfter`.
- **Claims are attributes by claim URI**: `who.attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']`.

## 5. Signing out

Two directions:

```ts
// The person signs out here: end the local session, then (optionally) at the identity provider.
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect(303, rp.logout({ reply: 'https://app.example.com/' })));
});

// The identity provider signs the person out of every relying party: it loads the reply URL as an image.
app.get('/wsfed', (req, res) => {
  if (!rp.isSignOutCleanup({ method: req.method, url: req.originalUrl })) return res.sendStatus(404);
  req.session.destroy(() => res.type('gif').send(ONE_PIXEL_GIF));
});
```

The cleanup arrives as a **cross-site image load**, which carries no `SameSite=Lax` cookie. To find the session, keep a second cookie for it, `SameSite=None; Secure`, scoped to the reply URL, as the demo does. Browsers that block third-party cookies drop even that, so the cleanup is best effort. The Shared Signals receiver (step 7) is what ends the session reliably.

## 6. Metadata

```ts
app.get('/FederationMetadata/2007-06/FederationMetadata.xml', (req, res) =>
  res.type('application/samlmetadata+xml').send(rp.metadata()));
```

## 7. Signed out by the identity provider: Shared Signals

A session at the application outlives a sign-out at the identity provider unless something tells it. `SignalsReceiver` is that something: it receives the identity provider's CAEP and RISC events and ends the matching sessions, whether or not the person's browser is open (see the [reference](../README.md#shared-signals-caep-and-risc)).

The relying party does not start a receiver. Start one in the application, unless the configuration sets `"signals": false`. The default is on. When it is false, do not start `SignalsReceiver` and do not require transmitter metadata; test `rp.config.signals !== false`. Sign-in is unchanged. The demo follows that.

```ts
const signals = new SignalsReceiver({
  transmitter: 'https://idp.example.com',
  tls: { ca: rp.config.idpCa, cert: rp.config.certificate!.toString(),
         key: rp.config.privateKey!.export({ type: 'pkcs8', format: 'pem' }) as string },
  onEndSessions: (ids) => ids.forEach((id) => req.sessionStore.destroy(id, () => {})),
});
await signals.start();
```

React to each event type with your own handler, `signals.on(EVENT.credentialChange, …)`: [Handling CAEP and RISC events](signals.md) has one for every CAEP and RISC type.

At the reply URL, after `req.session.regenerate()`, call `await signals.track(req.sessionID, who)`; at sign-out, `await signals.untrack(req.sessionID)`. Ending the session in the store is what matters: the browser's next request finds no session. Telling an open tab at once (Server-Sent Events, a WebSocket) is a courtesy on top; the demo does it.

## 8. Several people in one browser

The library is per sign-in, so several people in one browser is the application's session design. A pattern that fits a server-rendered application, and that the [demo](../../../demo/server.ts) implements:

- **One cookie names an account set** held on the server: the people signed in to this browser, each with their own session.
- **The URL says which person a tab is for**, as a stable per-account id (`/u/<account>/…`), not a position. A cookie is shared by every tab, so it can't say that.
- **Adding a person:** `rp.login({ forceAuthn: true })` (`wfresh=0`), so the identity provider authenticates someone instead of signing the current person in again. WS-Federation has no subject hint; an identity provider that reads one of its own takes it through `params`.

The trap: **the reply URL cannot read a `SameSite=Lax` cookie** when the response arrives, because it is a cross-site POST. Note the account set in the cookie that carries the request id: it is scoped to the reply URL, `SameSite=None` and signed. Otherwise every sign-in starts a new set and the browser forgets everyone else.

The identity provider must also let one browser hold several sessions. Otherwise a second sign-in ends the first person's IdP session, and its CAEP `session-revoked` then ends their session here too.

## 9. Several processes

The replay cache remembers accepted assertion IDs in one process's memory, and the Shared Signals session index likewise. Behind a load balancer, give every process one shared replay cache (and one shared `sessionIndex`, with the receiver running in a single process): anything with an atomic set-if-absent and an expiry.

```ts
const rp = await RelyingParty.fromFile('wsfed.json', {}, {
  replayCache: {
    async checkAndRecord(id, expiresAt) {
      const ok = await redis.set(`wsfed:${id}`, '1', { NX: true, PXAT: expiresAt.getTime() });
      return ok === null;   // true = seen before
    },
  },
});
```

## 10. Key rollover

For the identity provider's rollover, call `rp.refreshMetadata()` (or restart) after its metadata changes. For this relying party's key: generate a new pair (`generate-keys --force`), give the identity provider the new metadata, then restart.
