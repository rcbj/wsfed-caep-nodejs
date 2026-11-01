---
title: Running the demo
---

# Running the demo

The demo is a traditional server-rendered web application, [`demo/server.ts`](https://github.com/rcbj/wsfed-caep-nodejs/blob/main/demo/server.ts): `node:http`, no framework, run by Node as TypeScript. It signs people in with WS-Federation through `wsfed-caep-nodejs`, against iya-sts, and is signed out by iya-sts's CAEP and RISC events.

## 1. Set it up on iya-sts

```sh
npm install
ADMIN_API_CLIENT_SECRET=… WSFED_DEMO_USER_PASSWORD=… npm run configure-iya-sts
```

This makes the key pair and both metadata documents in `demo/generated/` and registers the relying party. See [Setting up iya-sts](configure.md).

## 2. Start it

```sh
docker compose up --build
```

Open <http://localhost:3000> and press **Sign in**. The browser goes to iya-sts's `/wsfed` with `wa=wsignin1.0`, the realm `http://localhost:3000/`, the reply URL `http://localhost:3000/wsfed`, a `wctx` naming this sign-in, and a `wreq` asking for a SAML 2.0 assertion. Sign in as `wsfed-demo-user`; iya-sts's page posts the WS-Trust response back to `/wsfed`.

To demand a sign-in method, pass `authenticationMethod` to `login()`. That value is the `wauth` parameter. Two factors is `http://schemas.microsoft.com/claims/multipleauthn`. The [server-side guide](guide.md#asking-for-a-sign-in-method-wauth) shows the call. iya-sts accepts one URI and answers a demand the session does not already meet with a step-up; the URIs are on [Configuring WS-Federation](https://rcbj.github.io/iya-sts/configure-ws-federation.html#wauth-demand-a-sign-in-method).

The page shows the NameID, the realm, the WS-Trust version of the response, the authentication instant and method, the session index, the assertion and its lifetime, and every claim iya-sts released.

## Signing out

- **Sign out of this account** ends the session here only.
- **Sign out here and at the identity provider** ends every account in this browser here, then sends the browser to iya-sts's `wsignout1.0`. iya-sts ends its session and loads each relying party's reply URL with `wa=wsignoutcleanup1.0` as an image.
- **`wsignoutcleanup1.0` at `/wsfed`** signs out every account in this browser and answers with a one-pixel GIF. The cleanup names no person, so it ends them all, as iya-sts's own cleanup does. It arrives as a cross-site image load, which carries no `SameSite=Lax` cookie, so the demo finds the browser's accounts by a separate `SameSite=None` cookie scoped to `/wsfed`. A browser that blocks third-party cookies drops that too; then CAEP `session-revoked` (below) is what ends the session.

## Several people in one browser

One browser can hold several signed-in people. The account bar at the top of a signed-in page lists them. **Add another account** signs one more person in (`wfresh=0`, so iya-sts asks who is signing in), and **Sign out of all accounts** ends them all. Each person has their own pages under `/u/<account>/`, stable for as long as they stay signed in, so two tabs can show two people side by side.

- **How the browser holds them.** One cookie, `aset`, names an *account set* kept on the server. Each person in it is a session of their own: their own sign-in, claims, CAEP and RISC events, and live event channel.
- **iya-sts must allow it.** With `authn.multipleAccounts` off, signing a second person in ends the first person's iya-sts session, and its CAEP `session-revoked` ends that person's account here too. The setup script turns the setting on.
- **Events stay with their person.** An event about one person reaches only that person's session and tabs.

## Shared Signals: signed out by the identity provider

`demo/wsfed.json`'s `ssf` block makes the demo a CAEP and RISC receiver. It keeps one poll stream at iya-sts, polls it every three seconds, and authenticates with mutual TLS using the relying party's own key pair.

Once you're signed in, the page has two tabs. **Identity** shows what the assertion said. **CAEP & RISC events** shows the stream (the receiver's state, the stream and its poll endpoint, every event type it delivers, which of them end the session, and a **Request verification event** button) and the event log: every CAEP and RISC event about this session or its person, newest first, with what the demo did, the subject and every member the event carried.

The page doesn't reload. `GET /u/<a>/events` is a Server-Sent Events stream that sends each event to that account's open tabs as soon as the receiver has it; `GET /u/<a>/api/signals?after=<id>` returns the same as JSON for a tab that cannot keep the stream open. Both read only that account's own log.

Sign in, then do one of these at iya-sts and watch the demo's tab:

- **Sign out** of iya-sts, or end the session on **Monitoring → Sessions**: CAEP `session-revoked` names that IdP session (the assertion's `SessionIndex`), and the demo session started from it ends.
- **Disable** the user on their **Directory → Users** page: RISC `account-disabled` ends every demo session of that person.
- **Change the user's password**: CAEP `credential-change` is listed on the page, and ends nothing (`endOn` decides which events end sessions).

## The container

`demo/generated/` is mounted read-only at `/app/demo/generated`: the key, the certificate, both metadata documents and iya-sts's TLS root. None of them is in the image.

The container uses the **host's network**, so that `https://localhost:8081`, the Shared Signals transmitter the demo's server polls, is the same address inside it as in the browser. On Docker Desktop, turn on host networking (**Settings → Resources → Network**).

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | The port the demo listens on. A loopback `realm` and `replyUrl` follow it. Re-run `configure-iya-sts` so iya-sts has the new reply URL. |
| `WSFED_CONFIG` | `demo/wsfed.json` | Another configuration file. |
| `SESSION_SECRET` | random per start | Signs the cookies. Set it to keep sign-ins in flight across a restart. |

To run it without a container: `npm run build && npm start`.

## How it handles the browser

- **`wsfed_pending`** holds the outstanding sign-in ids (the last three, so two tabs can sign in at once), HMAC-signed, scoped to `/wsfed`, for ten minutes. It is `SameSite=None; Secure`, because the response arrives as a **cross-site POST**, on which a `Lax` cookie is not sent. Browsers treat `http://localhost` as secure, so this works locally. A deployment needs HTTPS.
- **`aset`** is the account set, `SameSite=Lax; HttpOnly`, set after the response is accepted, and ending no later than the identity provider's `SessionNotOnOrAfter`.
- **`wsfed_cleanup`** names the account set for `wsignoutcleanup1.0`, sealed, `SameSite=None; Secure`, scoped to `/wsfed`.
- The pages send a strict Content-Security-Policy; the signed-in page allows only its own script (`/app.js`) and connections back to its own origin.
- A refused sign-in shows the `WsFedError` code and message. That is for the demo: a production application logs it and tells the person only that sign-in failed.
