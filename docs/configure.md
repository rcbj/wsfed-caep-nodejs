---
title: Setting up iya-sts
---

# Setting up iya-sts

iya-sts is a WS-Federation identity provider at `/wsfed`, with its federation metadata at `/FederationMetadata/2007-06/FederationMetadata.xml` and, for one registered relying party, at `/wsfed/metadata/<realm>`. In product mode it posts a token only to a **registered** relying party and only to a **registered** reply URL. Its default token is SAML 1.1; the library asks for SAML 2.0 with a `wreq` RequestSecurityToken, which iya-sts honours. See [iya-sts's WS-Federation page](https://rcbj.github.io/iya-sts/ws-federation.html).

## The script

```sh
npm install
ADMIN_API_CLIENT_SECRET=… npm run configure-iya-sts
```

[`scripts/configure-iya-sts.ts`](https://github.com/rcbj/wsfed-caep-nodejs/blob/main/scripts/configure-iya-sts.ts) reads [`demo/wsfed.json`](https://github.com/rcbj/wsfed-caep-nodejs/blob/main/demo/wsfed.json) and:

1. **Makes the key pair** if the files `privateKey` and `certificate` name do not exist yet (the same as `npm run generate-keys`). WS-Federation signs nothing; the key authenticates the Shared Signals receiver, and is what an identity provider that encrypts would encrypt to.
2. **Saves the iya-sts listener CA trust chain** to the `idpCa` file, on every run: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain the TLS handshake presents when that path does not answer. That first fetch is not verified (trust on first use). The trust anchor's subject and SHA-256 fingerprint are printed: compare them with the Root CA on iya-sts's **Server configuration → PKI** page. The demo image build copies that file in, so rebuild the image after running the script against a different iya-sts.
3. **Writes this relying party's federation metadata** to `demo/generated/rp-metadata.xml` and **registers the relying party**: `POST /admin-api/applications/create` with `protocols: ["wsfed"]`, the realm as identifier and `wsfedRealm`, and the reply URL in `wsfedReplyUrl`. When the application exists already, `POST /admin-api/applications/add` puts the reply URL on it (which also confirms one development mode merely observed).
4. **Turns on `authn.multipleAccounts` for the realm** (`POST /admin-api/config/set`), so one browser may hold several signed-in people. With the setting off, iya-sts ends the first person's session when the second signs in there, and sends CAEP `session-revoked` for it, which ends that person's account in the demo too.
5. **With an `ssf` block, and `signals` not false, gives the application Shared Signals access by its own certificate** (mutual TLS: no token, no secret). `"signals": false` skips this step: CAEP and RISC are off, SSF roles are not registered, and transmitter metadata is not required. The relying party is still registered for WS-Federation. Sign-in is unchanged. The default is on:
   - `POST /admin-api/applications/add`: `oauthAllowedScope` `ssf.manage`;
   - `POST /admin-api/roles/add-member`: the application in `SSF_MANAGE`;
   - `POST /admin-api/tls/trust/add`: the RP certificate as a client trust anchor;
   - `POST /admin-api/applications/add-certificate` (iya-sts #1227): the certificate stored on the application entry, which makes a handshake presenting it this application at `/ssf/*`.
6. **Fetches iya-sts's metadata for this relying party**, `/wsfed/metadata/<realm>`, checks it with the library's own reader, and saves it where `idpMetadata` points.
7. **Creates a test user**, `wsfed-demo-user`. Its password is `WSFED_DEMO_USER_PASSWORD`, or one is generated and printed once. With `WSFED_DEMO_USER_PASSWORD` set, an existing user's password is replaced.

Every step can be run again.

| Option | Use |
|---|---|
| `--idp url` | iya-sts is not at `https://localhost:8081` (or `$IYA_STS_URL`). A trust realm's base, `https://host/realm/<id>`, registers in that realm. |
| `--config path` | Another configuration file. |
| `--test-user name`, `--no-test-user` | Another test user, or none. |
| `--dry-run` | Print the plan and send nothing. |

### The management API secret

The script mints a token as iya-sts's seeded client `sts-api-client` (`client_credentials`, HTTP Basic, audience `<idp>/admin-api`, scope `admin:read admin:write`). The secret is `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET`. [iya-sts's management API page](https://rcbj.github.io/iya-sts/management-api.html) says where a compose stack keeps it.

## What iya-sts does, in product mode

- **The relying party must be registered.** A `wsignin1.0` for an unknown `wtrealm` is a 404 page before the sign-in screen.
- **The reply URL must be registered**, matched exactly.
- **The assertion is signed** with the realm's XML signing key, published in the metadata. Its Issuer is the realm's OAuth 2.0 issuer, the same string as the metadata's entityID.
- **No token encryption** in the passive profile, so the demo leaves `wantAssertionsEncrypted` off.
- **`wsignout1.0`** loads each relying party's reply URL with `wa=wsignoutcleanup1.0` as an image.

## Doing it by hand

On iya-sts's console: **Applications → New application**, identifier the realm, tick **WS-Federation**, and enter the reply URL in `wsfedReplyUrl`. Then save `/wsfed/metadata/<realm>` where `idpMetadata` points. See [Configuring WS-Federation](https://rcbj.github.io/iya-sts/configure-ws-federation.html).

## Another identity provider

The library needs nothing iya-sts-specific. Register the realm and reply URL at any WS-Federation identity provider (AD FS: a relying party trust, with `rp-metadata.xml` or by hand, issuing SAML 2.0), and save its federation metadata where `idpMetadata` points (or set `idpMetadata` to its URL, with `idpCa` if its TLS certificate chains to a private root). If it refuses `wreq`, set `requestTokenType` to `false` and configure it to issue SAML 2.0 to the realm.
