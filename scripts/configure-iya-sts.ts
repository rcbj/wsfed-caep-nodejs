#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
/**
 * Sets up the demo against a running iya-sts as a WS-Federation relying party:
 *
 *   1. the relying party's key pair, if the files the configuration names do not exist yet (the same as
 *      `npm run generate-keys`). WS-Federation signs nothing; the key is the Shared Signals receiver's TLS
 *      client certificate, and what an identity provider that encrypts would encrypt to;
 *   2. the identity provider's TLS root, if the configuration's `idpCa` file does not exist yet: taken
 *      from the TLS handshake (trust on first use) and its fingerprint printed, for you to compare with
 *      iya-sts's Server configuration → PKI page;
 *   3. this relying party's federation METADATA, from the configuration's certificate when it has
 *      one, with the realm and reply URL this run registers (a loopback pair follows PORT), written
 *      to demo/generated/rp-metadata.xml for an identity provider that reads one, and the relying party
 *      REGISTERED on iya-sts: an application declared for the `wsfed` protocol family, its identifier and
 *      `wsfedRealm` the realm, and the reply URL in `wsfedReplyUrl` — product mode posts a token only to a
 *      registered reply URL, matched exactly. When the application exists already, the reply URL is added
 *      to it (`applications/add`, which also confirms an address development mode merely observed);
 *   3a. turns on `authn.multipleAccounts` for the realm: the demo signs several people in to one browser,
 *      and with the setting off, iya-sts would END one person's session when the next signs in there
 *      (and send CAEP session-revoked for it, which ends that person's account here);
 *   3b. with an `ssf` block in the configuration, the Shared Signals receiver's access, by MUTUAL TLS
 *      with the relying party's own certificate (no token, no secret): the application declares
 *      `ssf.manage` and is made a member of the SSF_MANAGE role, the certificate is installed as a
 *      client trust anchor (`/admin-api/tls/trust/add`) and stored on the application entry
 *      (`/admin-api/applications/add-certificate`, iya-sts #1227), which is what makes the handshake's
 *      certificate this application at `/ssf/*`;
 *   4. iya-sts's federation METADATA for this relying party (`/wsfed/metadata/<realm>`), checked with the
 *      library's own reader and written where the configuration's `idpMetadata` points, so the library
 *      learns the identity provider (entityID, passive requestor endpoint, signing certificate) from it;
 *   5. a test user to sign in as.
 *
 *   ADMIN_API_CLIENT_SECRET=… node scripts/configure-iya-sts.ts
 *   node scripts/configure-iya-sts.ts --idp https://localhost:8081 --config demo/wsfed.json
 *   node scripts/configure-iya-sts.ts --dry-run          # print the plan, send nothing
 *
 * The management API token is minted as iya-sts's seeded client `sts-api-client` (client_credentials,
 * HTTP Basic), audienced to `<idp>/admin-api`, scope `admin:read admin:write`. The secret is
 * ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET; iya-sts's docs/management-api.md says where
 * a compose stack keeps it.
 */

import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { connect, type PeerCertificate } from 'node:tls';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { main as cli } from '../packages/wsfed-caep-nodejs/src/cli.ts';
import { resolveConfig, type WsFedConfig } from '../packages/wsfed-caep-nodejs/src/config.ts';
import { send } from '../packages/wsfed-caep-nodejs/src/http.ts';
import { readIdpMetadata } from '../packages/wsfed-caep-nodejs/src/metadata.ts';
import { RelyingParty } from '../packages/wsfed-caep-nodejs/src/relying-party.ts';
import { demoPort, endpointsFor } from './redirects.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export function usage(): string {
  return `Usage: node scripts/configure-iya-sts.ts [--config path] [--idp url] [--public-url url]
                                        [--test-user name | --no-test-user] [--dry-run]

  --config        The demo's WS-Federation configuration (default: demo/wsfed.json)
  --idp           iya-sts's base URL; the realm's, e.g. https://host/realm/acme, for a trust realm
                  (default: $IYA_STS_URL or https://localhost:8081)
  --public-url    Replace the origin of the file's realm and reply URL with this URL, and keep
                  their paths (default: unset; $PUBLIC_URL). Without it, a loopback realm and
                  reply URL follow the running demo's PORT, then $PORT. Any other host is left
                  as written.
  --test-user     The test user to create (default: wsfed-demo-user). Its password is
                  $WSFED_DEMO_USER_PASSWORD, or one is generated and printed once. With
                  $WSFED_DEMO_USER_PASSWORD set, an existing user's password is replaced.
  --no-test-user  Do not create a test user.
  --dry-run       Print what would be done, and send nothing.

The management API secret is ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET.`;
}

export interface Args {
  config: string;
  idp: string;
  publicUrl: string;
  /** Set when --public-url or PUBLIC_URL was given. The default does not count. */
  publicUrlGiven: boolean;
  testUser: string;
  dryRun: boolean;
  help: boolean;
}

export function parseArgs(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): Args {
  const out: Args = {
    config: resolve(repoRoot, 'demo/wsfed.json'),
    idp: (env.IYA_STS_URL || 'https://localhost:8081').replace(/\/+$/, ''),
    publicUrl: (env.PUBLIC_URL || 'http://localhost:3000').replace(/\/+$/, ''),
    publicUrlGiven: Boolean(env.PUBLIC_URL),
    testUser: 'wsfed-demo-user',
    dryRun: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    const value = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${arg} needs a value\n${usage()}`);
      return v;
    };
    if (arg === '--help' || arg === '-h') out.help = true;
    else if (arg === '--config') out.config = resolve(value());
    else if (arg === '--idp') out.idp = value().replace(/\/+$/, '');
    else if (arg === '--public-url') {
      out.publicUrl = value().replace(/\/+$/, '');
      out.publicUrlGiven = true;
    } else if (arg === '--test-user') out.testUser = value().trim();
    else if (arg === '--no-test-user') out.testUser = '';
    else if (arg === '--dry-run') out.dryRun = true;
    else throw new Error(`Unknown argument ${arg}\n${usage()}`);
  }
  const u = new URL(out.idp);
  if (u.protocol !== 'https:') throw new Error(`--idp must be https, not ${out.idp}`);
  if (!out.publicUrl) throw new Error('--public-url is empty');
  return out;
}

/** The realm, the reply URL and the files the configuration names, resolved against it. */
export interface DemoFiles {
  realm: string;
  replyUrl: string;
  key: string;
  cert: string;
  idpMetadata: string;
  idpCa: string | undefined;
  rpMetadata: string;
  /** The Shared Signals transmitter, when the configuration has an `ssf` block. */
  ssfTransmitter: string | undefined;
}

export function filesOf(configPath: string): DemoFiles {
  const raw = JSON.parse(readFileSync(configPath, 'utf8')) as Record<string, string | undefined> & { ssf?: { transmitter?: string } };
  const base = dirname(configPath);
  const at = (p: string | undefined, what: string) => {
    if (!p || p.includes('-----BEGIN') || /^https?:/.test(p) || p.startsWith('<')) {
      throw new Error(`${configPath}'s ${what} must be a file path for this script to write`);
    }
    return isAbsolute(p) ? p : resolve(base, p);
  };
  if (!raw.realm) throw new Error(`${configPath} has no realm`);
  if (!raw.replyUrl) throw new Error(`${configPath} has no replyUrl`);
  const key = at(raw.privateKey, 'privateKey');
  return {
    realm: raw.realm,
    replyUrl: raw.replyUrl,
    key,
    cert: at(raw.certificate, 'certificate'),
    idpMetadata: at(raw.idpMetadata, 'idpMetadata'),
    idpCa: raw.idpCa ? at(raw.idpCa, 'idpCa') : undefined,
    rpMetadata: resolve(dirname(key), 'rp-metadata.xml'),
    ssfTransmitter: raw.ssf?.transmitter,
  };
}

/** The realm's base and the origin a token is minted at: `/realm/<id>` is kept, anything else refused. */
export function realmOf(idp: string): { origin: string; base: string } {
  const u = new URL(idp);
  const path = u.pathname.replace(/\/+$/, '');
  if (path && !/^\/realm\/[^/]+$/.test(path)) throw new Error(`--idp must be iya-sts's base URL or a realm's (/realm/<id>), not ${idp}`);
  return { origin: u.origin, base: `${u.origin}${path}` };
}

/** iya-sts's federation metadata for one registered relying party. */
export const idpMetadataUrl = (base: string, realm: string) => `${base}/wsfed/metadata/${encodeURIComponent(realm)}`;

/** The realm setting that lets one browser hold several signed-in people (iya-sts #561). */
export const MULTIPLE_ACCOUNTS = { key: 'authn.multipleAccounts', value: true } as const;

/** The management API calls, in order, as `{ method, path, body, why }`. Pure, for --dry-run and the tests. */
export function planFor(files: DemoFiles, base: string, testUser: string) {
  const calls: Array<{ method: string; path: string; body: unknown; why: string }> = [
    {
      method: 'POST', path: `${base}/admin-api/applications/create`, why: `register the relying party ${files.realm}`,
      body: {
        identifier: files.realm, name: 'wsfed-caep-nodejs demo', protocols: ['wsfed'],
        fields: { wsfedRealm: [files.realm], wsfedReplyUrl: [files.replyUrl] },
      },
    },
    {
      method: 'POST', path: `${base}/admin-api/applications/add`, why: '(only if it already exists) register the reply URL on it',
      body: { application: files.realm, attribute: 'wsfedReplyUrl', value: files.replyUrl },
    },
    { method: 'POST', path: `${base}/admin-api/config/set`, why: 'let one browser hold several accounts', body: MULTIPLE_ACCOUNTS },
    { method: 'GET', path: idpMetadataUrl(base, files.realm), body: undefined, why: `fetch the IdP metadata into ${files.idpMetadata}` },
  ];
  if (files.ssfTransmitter) calls.splice(calls.length - 1, 0, ...ssfCalls(files, base, '<the RP certificate>'));
  if (testUser) calls.push({ method: 'POST', path: `${base}/admin-api/users/create`, why: `create the test user ${testUser}`, body: { username: testUser } });
  return calls;
}

/**
 * The Shared Signals receiver's access, authenticated by the RP's certificate over mutual TLS: declare
 * the SSF write scope (which includes read; iya-sts reads a certificate's scopes literally), hold the
 * role that authorizes it, trust the self-signed certificate at the handshake, and store it on the
 * application so the handshake's certificate IS this application.
 */
export function ssfCalls(files: DemoFiles, base: string, certificatePem: string) {
  return [
    { method: 'POST', path: `${base}/admin-api/applications/add`, why: 'declare the Shared Signals write scope',
      body: { application: files.realm, attribute: 'oauthAllowedScope', value: 'ssf.manage' } },
    { method: 'POST', path: `${base}/admin-api/roles/add-member`, why: 'hold SSF_MANAGE, which authorizes it',
      body: { role: 'SSF_MANAGE', kind: 'application', member: files.realm } },
    { method: 'POST', path: `${base}/admin-api/tls/trust/add`, why: 'trust the RP certificate at the TLS handshake',
      body: { certificates: certificatePem } },
    { method: 'POST', path: `${base}/admin-api/applications/add-certificate`, why: 'store the RP certificate on the application',
      body: { application: files.realm, certificate: certificatePem } },
  ];
}

/** The root of the chain the server presents, taken from the handshake without verifying it. */
function fetchTlsRoot(origin: string): Promise<X509Certificate> {
  const u = new URL(origin);
  return new Promise((resolvePromise, reject) => {
    const socket = connect({ host: u.hostname, port: Number(u.port || 443), servername: u.hostname, rejectUnauthorized: false }, () => {
      let cert = socket.getPeerCertificate(true) as PeerCertificate & { issuerCertificate?: PeerCertificate };
      while (cert.issuerCertificate && cert.issuerCertificate !== cert && cert.issuerCertificate.raw) cert = cert.issuerCertificate;
      socket.end();
      resolvePromise(new X509Certificate(cert.raw));
    });
    socket.on('error', reject);
  });
}

async function json(url: string, ca: string | undefined, init: { method?: string; headers?: Record<string, string>; body?: string }) {
  const tls = ca ? { ca } : {};
  const answer = await send(url, init, tls, 'config');
  let body: Record<string, unknown> = {};
  try {
    body = answer.body ? JSON.parse(answer.body) : {};
  } catch {
    throw new Error(`${init.method ?? 'GET'} ${url} answered ${answer.status} with non-JSON: ${answer.body.slice(0, 300)}`);
  }
  if (answer.status === 401 || answer.status === 403) throw new Error(`${init.method ?? 'GET'} ${url} answered ${answer.status}: ${JSON.stringify(body).slice(0, 300)}`);
  return { status: answer.status, body };
}

const errorsOf = (body: Record<string, unknown>) => ([] as unknown[]).concat(body.errors ?? []).map(String);

async function mintAdminToken(origin: string, base: string, ca: string | undefined, secret: string): Promise<string> {
  const form = new URLSearchParams({ grant_type: 'client_credentials', scope: 'admin:read admin:write', resource: `${base}/admin-api` });
  const reply = await json(`${base}/oauth2/token`, ca, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`sts-api-client:${secret}`).toString('base64')}` },
    body: form.toString(),
  });
  if (reply.status !== 200 || typeof reply.body.access_token !== 'string') {
    throw new Error(`the token endpoint at ${origin} answered ${reply.status} ${JSON.stringify(reply.body).slice(0, 300)}`);
  }
  return reply.body.access_token;
}

/** PORT from the running wsfed-demo container, when compose has one. Docker being absent is not an error. */
export function containerPort(cwd = repoRoot): string | undefined {
  try {
    const id = execFileSync('docker', ['compose', 'ps', '-q', 'wsfed-demo'], {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim().split('\n')[0];
    if (!id) return undefined;
    const env = execFileSync('docker', ['inspect', '-f', '{{range .Config.Env}}{{println .}}{{end}}', id], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    });
    return env.split('\n').find((line) => line.startsWith('PORT='))?.slice('PORT='.length);
  } catch {
    return undefined;
  }
}

/**
 * This relying party's metadata, from the configuration's certificate when it has one, with the realm
 * and reply URL this run registers. The file on disk is not what is written: a loopback realm is a
 * different application on a different port.
 */
export function metadataFor(configPath: string, realm: string, replyUrl: string): string {
  const raw = JSON.parse(readFileSync(configPath, 'utf8')) as WsFedConfig;
  delete raw.idpCa;
  raw.realm = realm;
  raw.replyUrl = replyUrl;
  return new RelyingParty(resolveConfig(raw, dirname(resolve(configPath))), undefined).metadata();
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return;
  }
  const files = filesOf(args.config);
  // The realm is the application identifier (wtrealm) and the reply URL is wreply. A loopback pair
  // follows the port the demo listens on, so a port change registers that realm. An explicit public
  // URL replaces the origin instead. pollIntervalMs is a timer and is not an address.
  const port = demoPort(process.env.PORT, containerPort());
  const endpoints = endpointsFor(files.realm, files.replyUrl, {
    publicUrl: args.publicUrl, publicUrlGiven: args.publicUrlGiven, port,
  });
  files.realm = endpoints.realm;
  files.replyUrl = endpoints.replyUrl;
  const { origin, base } = realmOf(args.idp);

  if (args.dryRun) {
    if (!existsSync(files.key)) console.log(`# would generate the key pair ${files.key}, ${files.cert}`);
    if (files.idpCa && !existsSync(files.idpCa)) console.log(`# would save ${origin}'s TLS root to ${files.idpCa}`);
    console.log(`# would write ${files.rpMetadata}`);
    for (const c of planFor(files, base, args.testUser)) {
      console.log(`${c.method} ${c.path}  # ${c.why}${c.body ? `\n${JSON.stringify(c.body, null, 2)}` : ''}`);
    }
    return;
  }

  // 1. The key pair.
  if (!existsSync(files.key) && !existsSync(files.cert)) {
    console.log('No key pair yet; generating one.');
    await cli(['generate-keys', '--config', args.config]);
  }

  // 2. The IdP's TLS root, trusted on first use.
  let ca: string | undefined;
  if (files.idpCa) {
    if (!existsSync(files.idpCa)) {
      const root = await fetchTlsRoot(origin);
      mkdirSync(dirname(files.idpCa), { recursive: true });
      writeFileSync(files.idpCa, root.toString());
      console.log(`Saved ${origin}'s TLS root to ${files.idpCa} (trusted on first use):`);
      console.log(`  ${root.subject.replace(/\n/g, ', ')}\n  sha256 ${root.fingerprint256}`);
      console.log('  Compare it with the Root CA on iya-sts\'s Server configuration → PKI page.');
    }
    ca = readFileSync(files.idpCa, 'utf8');
  }

  // 3. The RP metadata uses the realm and reply URL this run registers, then the relying party.
  const rpMetadataXml = metadataFor(args.config, files.realm, files.replyUrl);
  mkdirSync(dirname(files.rpMetadata), { recursive: true });
  writeFileSync(files.rpMetadata, rpMetadataXml);
  console.log(`Wrote the relying party metadata to ${files.rpMetadata}`);
  const secret = process.env.ADMIN_API_CLIENT_SECRET || process.env.STS_ADMIN_API_CLIENT_SECRET || '';
  if (!secret) throw new Error('neither ADMIN_API_CLIENT_SECRET nor STS_ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted.');
  const token = await mintAdminToken(origin, base, ca, secret);
  const api = (path: string, body: unknown) => json(`${base}/admin-api${path}`, ca, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  const [create, addReply] = planFor(files, base, args.testUser);
  const created = await api('/applications/create', create!.body);
  if (created.body.ok) {
    console.log(`Registered the relying party ${files.realm}, replying to ${files.replyUrl}.`);
  } else if (errorsOf(created.body).some((e) => /already in this registry/i.test(e))) {
    const added = await api('/applications/add', addReply!.body);
    if (!added.body.ok && !/already/i.test(errorsOf(added.body).join(' '))) {
      throw new Error(`iya-sts refused the reply URL: ${JSON.stringify(added.body).slice(0, 500)}`);
    }
    console.log(`${files.realm} was registered already; ${files.replyUrl} is one of its reply URLs.`);
  } else {
    throw new Error(`iya-sts refused to create ${files.realm}: ${JSON.stringify(created.body).slice(0, 500)}`);
  }

  // 3a. Several people in one browser.
  const multiple = await api('/config/set', MULTIPLE_ACCOUNTS);
  if (!multiple.body.ok) throw new Error(`setting authn.multipleAccounts was refused: ${JSON.stringify(multiple.body).slice(0, 300)}`);
  console.log('authn.multipleAccounts is on: one browser may hold several signed-in people.');

  // 3b. The Shared Signals receiver's access.
  if (files.ssfTransmitter) {
    const certificatePem = readFileSync(files.cert, 'utf8');
    for (const call of ssfCalls(files, base, certificatePem)) {
      const r = await api(call.path.slice(`${base}/admin-api`.length), call.body);
      const errors = errorsOf(r.body).join(' ');
      // Each step is idempotent from here: a value already there, a member already holding the role, an
      // anchor already installed, a certificate already stored on this entry.
      if (!r.body.ok && !/already/i.test(errors)) throw new Error(`${call.why}: refused: ${JSON.stringify(r.body).slice(0, 400)}`);
      if (!r.body.ok) console.log(`  ${call.why}: already so (${errors.slice(0, 160)})`);
    }
    console.log(`Shared Signals: ${files.realm} holds SSF_MANAGE and authenticates to /ssf/* with its own certificate (mutual TLS).`);
  }

  // 4. The IdP metadata, for the library.
  const url = idpMetadataUrl(base, files.realm);
  const fetched = await send(url, { headers: { accept: 'application/samlmetadata+xml' } }, ca ? { ca } : {}, 'metadata');
  if (fetched.status !== 200) throw new Error(`${url} answered ${fetched.status}`);
  const idp = readIdpMetadata(fetched.body);
  mkdirSync(dirname(files.idpMetadata), { recursive: true });
  writeFileSync(files.idpMetadata, fetched.body);
  console.log(`Saved the IdP metadata to ${files.idpMetadata}:`);
  console.log(`  entityID     ${idp.entityId}`);
  console.log(`  passive      ${idp.passiveRequestorEndpoint}`);
  console.log(`  token types  ${idp.tokenTypesOffered.join(', ') || '(not stated)'}`);

  // 5. The test user.
  if (args.testUser) {
    const found = await json(`${base}/admin-api/users?user=${encodeURIComponent(args.testUser)}`, ca, { headers: { accept: 'application/json', authorization: `Bearer ${token}` } });
    const password = process.env.WSFED_DEMO_USER_PASSWORD || '';
    if (found.body.known === true && password) {
      const set = await api('/users/set-password', { user: args.testUser, password, passwordConfirm: password });
      if (!set.body.ok) throw new Error(`setting ${args.testUser}'s password was refused: ${JSON.stringify(set.body).slice(0, 300)}`);
      console.log(`User ${args.testUser} already exists; its password is now WSFED_DEMO_USER_PASSWORD.`);
    } else if (found.body.known === true) {
      console.log(`User ${args.testUser} already exists; its password is unchanged (set WSFED_DEMO_USER_PASSWORD to replace it).`);
    } else {
      const attributes = { cn: `WS-Fed Demo ${args.testUser}`, givenName: 'WS-Fed', sn: 'Demo', displayName: `WS-Fed Demo ${args.testUser}`, mail: `${args.testUser}@wsfed-demo.test` };
      const body = password
        ? { username: args.testUser, invent: false, credential: 'password', password, passwordConfirm: password, attributes }
        : { username: args.testUser, invent: false, credential: 'generate', attributes };
      const made = await api('/users/create', body);
      if (!made.body.ok) throw new Error(`creating ${args.testUser} was refused: ${JSON.stringify(made.body).slice(0, 300)}`);
      console.log(`Created user ${args.testUser}.`);
      if (made.body.password) console.log(`Generated password for ${args.testUser} (shown once): ${String(made.body.password)}`);
    }
  }
  console.log('Done. Start the demo with: docker compose up --build');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((err: Error) => {
    console.error(err.message);
    process.exit(1);
  });
}
