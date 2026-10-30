// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The relying party: what an application calls. The Web (Passive) Requestor Profile of WS-Federation 1.2
// (section 13) in five calls:
//
//   login()            the URL that sends the browser to the identity provider with wa=wsignin1.0; the
//                      application keeps the request's id with the browser (a cookie) until it comes back;
//   handleReply()      reads the sign-in response POSTed to the reply URL (wa=wsignin1.0, wresult, wctx),
//                      checks that wctx names a request this browser has outstanding, validates the SAML
//                      2.0 assertion, and returns who signed in;
//   logout()           the URL that signs the person out at the identity provider (wa=wsignout1.0);
//   isSignOutCleanup() whether a request at the reply URL is the identity provider's wsignoutcleanup1.0;
//   metadata()         this relying party's federation metadata, for the identity provider.
//
// THE CORRELATION. A wsignin1.0 request is not signed and its response answers no request id: the SAML
// assertion carries no InResponseTo. The one thing the identity provider returns unchanged is `wctx`, so
// that is where the request id goes (`id=<id>`, with the application's own state as `ru=<state>`, the
// shape WIF uses). Checking it at the reply URL is what stops a response from being pushed into a browser
// that never asked for one (login CSRF). It is not part of what the identity provider signs: the
// assertion's signature, audience and lifetime are what make the sign-in genuine.
//
// It speaks no web framework: handleReply() takes the method, the URL and the parsed or raw form body,
// which every framework (and node:http) has.

import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readConfigFile, resolveConfig, type ResolvedConfig, type WsFedConfig } from './config.ts';
import { WsFedError } from './errors.ts';
import { send, type BackChannelOptions } from './http.ts';
import { readIdpMetadata, writeRpMetadata, type IdpMetadata } from './metadata.ts';
import { MemoryReplayCache, type ReplayCache } from './replay.ts';
import { validateToken, type WsFedLogin } from './token.ts';
import { NS, SAML2_TOKEN_TYPE } from './xml.ts';

/** Options that are code rather than configuration. */
export interface RelyingPartyOptions {
  /** Where accepted assertion IDs are remembered. Default: this process's memory. */
  replayCache?: ReplayCache;
}

/** Per sign-in choices. */
export interface LoginOptions {
  /** Application state that comes back unchanged in `wctx` (at most 1024 bytes). Typically where to go after sign-in. */
  relayState?: string;
  /** Make the identity provider authenticate the person again even if it has a session: `wfresh=0`. */
  forceAuthn?: boolean;
  /** `wfresh`: the most minutes since the person authenticated that this sign-in accepts. `forceAuthn` wins. */
  freshness?: number;
  /** `wauth`: the authentication method the identity provider must use, e.g. `http://schemas.microsoft.com/claims/multipleauthn`. */
  authenticationMethod?: string;
  /** `whr`: the home realm, the account provider the person belongs to, for an identity provider that federates. */
  homeRealm?: string;
  /** Further query parameters, for an identity provider that reads its own (e.g. `login_hint`). The protocol's own cannot be replaced. */
  params?: Record<string, string>;
}

/** Where to send the browser. Keep `id` with the browser until it returns. */
export interface LoginRequest {
  /** This request's id: it is in `wctx`, and handleReply() expects it back. */
  id: string;
  /** The identity provider's passive requestor endpoint with the wsignin1.0 parameters: redirect the browser here. */
  url: string;
  /** The `wctx` sent. */
  wctx: string;
}

/** The parts of an HTTP request at the reply URL that this module reads. */
export interface ReplyRequest {
  /** `GET` or `POST`. */
  method: string;
  /** The request URL: the path and query as received (`req.url`, `req.originalUrl`), or an absolute URL. */
  url: string;
  /** For POST: the form body, raw (`application/x-www-form-urlencoded` text) or already parsed. */
  body?: string | Record<string, unknown> | undefined;
}

export interface ReplyOptions {
  /** The sign-in request id(s) this browser has outstanding, as kept from {@link RelyingParty.login}. */
  requestId?: string | readonly string[] | undefined;
}

const MAX_RELAY_STATE = 1024;
const PROTOCOL_PARAMS = new Set(['wa', 'wtrealm', 'wreply', 'wctx', 'wct', 'wreq', 'wreqptr', 'wfresh', 'wauth', 'whr']);

export class RelyingParty {
  readonly config: ResolvedConfig;
  #idp: IdpMetadata | undefined;
  readonly #replayCache: ReplayCache;

  constructor(config: ResolvedConfig, idp: IdpMetadata | undefined, options: RelyingPartyOptions = {}) {
    this.config = config;
    this.#idp = idp;
    this.#replayCache = options.replayCache ?? new MemoryReplayCache();
  }

  /** Builds a relying party from a configuration object and loads the identity provider's metadata. */
  static async create(config: WsFedConfig, options: RelyingPartyOptions & { baseDir?: string } = {}): Promise<RelyingParty> {
    const rp = new RelyingParty(resolveConfig(config, options.baseDir), undefined, options);
    await rp.refreshMetadata();
    return rp;
  }

  /** Builds a relying party from a JSON configuration file and loads the identity provider's metadata. */
  static async fromFile(path: string, overrides: Partial<WsFedConfig> = {}, options: RelyingPartyOptions = {}): Promise<RelyingParty> {
    const rp = new RelyingParty(readConfigFile(path, overrides), undefined, options);
    await rp.refreshMetadata();
    return rp;
  }

  /** The identity provider, as its metadata describes it. */
  get idp(): IdpMetadata {
    if (!this.#idp) throw new WsFedError('metadata', 'the identity provider\'s metadata has not been loaded');
    return this.#idp;
  }

  get #tls(): BackChannelOptions {
    return this.config.idpCa ? { ca: this.config.idpCa } : {};
  }

  /** (Re)reads the identity provider's metadata from where the configuration says it is. Call it to pick up a key rollover. */
  async refreshMetadata(): Promise<IdpMetadata> {
    const source = this.config.idpMetadata;
    let xml: string;
    if (source.startsWith('<')) {
      xml = source;
    } else if (/^https?:\/\//.test(source)) {
      const answer = await send(source, { headers: { accept: 'application/samlmetadata+xml, application/xml, text/xml' } }, this.#tls, 'metadata');
      if (answer.status !== 200) throw new WsFedError('metadata', `${source} answered HTTP ${answer.status}`);
      xml = answer.body;
    } else {
      try {
        xml = readFileSync(source, 'utf8');
      } catch (err) {
        throw new WsFedError('metadata', `the identity provider metadata file ${source} cannot be read`, { cause: err });
      }
    }
    this.#idp = readIdpMetadata(xml, this.config.idpEntityId);
    return this.#idp;
  }

  /** This relying party's federation metadata. Serve it, or give it to the identity provider. */
  metadata(): string {
    return writeRpMetadata({
      realm: this.config.realm,
      replyUrl: this.config.replyUrl,
      ...(this.config.certificate ? { certificate: this.config.certificate } : {}),
    });
  }

  /** A wsignin1.0 request. Redirect the browser to `url`, and keep `id` with that browser. */
  login(options: LoginOptions = {}): LoginRequest {
    if (options.relayState !== undefined && Buffer.byteLength(options.relayState) > MAX_RELAY_STATE) {
      throw new WsFedError('config', `relayState is longer than ${MAX_RELAY_STATE} bytes`);
    }
    const id = randomBytes(20).toString('hex');
    const wctx = new URLSearchParams({ id, ...(options.relayState !== undefined ? { ru: options.relayState } : {}) }).toString();
    const q = new URLSearchParams();
    q.set('wa', 'wsignin1.0');
    q.set('wtrealm', this.config.realm);
    q.set('wreply', this.config.replyUrl);
    q.set('wctx', wctx);
    q.set('wct', new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'));
    if (this.config.requestTokenType) {
      // The standard way to ask for a SAML 2.0 assertion: a RequestSecurityToken, by value, naming its type.
      q.set('wreq', `<wst:RequestSecurityToken xmlns:wst="${NS.trust13}"><wst:TokenType>${SAML2_TOKEN_TYPE}</wst:TokenType></wst:RequestSecurityToken>`);
    }
    if (options.forceAuthn) q.set('wfresh', '0');
    else if (options.freshness !== undefined) {
      if (!Number.isInteger(options.freshness) || options.freshness < 0) throw new WsFedError('config', 'freshness is a whole number of minutes');
      q.set('wfresh', String(options.freshness));
    }
    if (options.authenticationMethod) q.set('wauth', options.authenticationMethod);
    if (options.homeRealm) q.set('whr', options.homeRealm);
    for (const [k, v] of Object.entries(options.params ?? {})) {
      if (PROTOCOL_PARAMS.has(k)) throw new WsFedError('config', `params cannot set ${k}; it is the protocol's own`);
      q.set(k, v);
    }
    const endpoint = this.idp.passiveRequestorEndpoint;
    return { id, url: `${endpoint}${endpoint.includes('?') ? '&' : '?'}${q.toString()}`, wctx };
  }

  /**
   * Reads and validates the sign-in response at the reply URL: a POST of `wa=wsignin1.0`, `wresult` (a
   * WS-Trust RequestSecurityTokenResponse holding a signed SAML 2.0 assertion) and `wctx`. Returns who
   * signed in; throws a {@link WsFedError} otherwise.
   */
  async handleReply(request: ReplyRequest, options: ReplyOptions = {}): Promise<WsFedLogin> {
    const idp = this.idp;
    const { form, query } = paramsOf(request);
    const wa = form.get('wa') ?? query.get('wa');
    if (wa === 'wsignoutcleanup1.0' || wa === 'wsignout1.0') throw new WsFedError('message', `the request is ${wa}, a sign-out, not a sign-in response; see isSignOutCleanup()`);
    if (request.method.toUpperCase() !== 'POST') {
      throw new WsFedError('message', 'a sign-in response is POSTed (WS-Federation 13.2.2); this request is a GET');
    }
    if (wa !== 'wsignin1.0') throw new WsFedError('message', `the request's wa is ${wa ?? '(none)'}, not wsignin1.0`);
    if (form.has('wresultptr')) throw new WsFedError('message', 'the response is by reference (wresultptr), which is never dereferenced; only wresult is accepted');
    const wresult = form.get('wresult');
    if (!wresult) throw new WsFedError('message', 'the request carries no wresult');

    // The correlation, before any cryptography: a response this browser never asked for stops here.
    const wctx = new URLSearchParams(form.get('wctx') ?? '');
    const requestId = wctx.get('id') ?? undefined;
    const expected = options.requestId === undefined ? [] : ([] as string[]).concat(options.requestId);
    if (requestId !== undefined) {
      if (!expected.includes(requestId)) throw new WsFedError('validation', `the response answers ${requestId}, which is not a sign-in this browser has outstanding`);
    } else if (!this.config.allowUnsolicited) {
      throw new WsFedError('validation', 'the response is unsolicited (its wctx names no request), and unsolicited responses are not accepted');
    }

    const token = await validateToken(wresult, {
      realm: this.config.realm,
      replyUrl: this.config.replyUrl,
      idpEntityId: idp.entityId,
      idpCertificates: idp.signingCertificates,
      decryptionKey: this.config.privateKey,
      clockSkewMs: this.config.clockSkewMs,
      wantAssertionsEncrypted: this.config.wantAssertionsEncrypted,
      replayCache: this.#replayCache,
    });
    const login: WsFedLogin = { ...token };
    if (requestId !== undefined) login.requestId = requestId;
    const relayState = wctx.get('ru');
    if (relayState !== null) login.relayState = relayState;
    return login;
  }

  /**
   * Whether a request at the reply URL is the identity provider's sign-out cleanup (`wa=wsignoutcleanup1.0`,
   * or `wsignout1.0` from one that sends that instead): end this browser's session, and answer with an image
   * or an empty 200, because the identity provider loads it as an image.
   */
  isSignOutCleanup(request: ReplyRequest): boolean {
    const { form, query } = paramsOf(request);
    const wa = form.get('wa') ?? query.get('wa');
    return wa === 'wsignoutcleanup1.0' || wa === 'wsignout1.0';
  }

  /** The URL that signs the person out at the identity provider (wsignout1.0), and then offers `reply`. */
  logout(options: { reply?: string } = {}): string {
    const q = new URLSearchParams({ wa: 'wsignout1.0', wtrealm: this.config.realm });
    if (options.reply) q.set('wreply', options.reply);
    const endpoint = this.idp.passiveRequestorEndpoint;
    return `${endpoint}${endpoint.includes('?') ? '&' : '?'}${q.toString()}`;
  }
}

function paramsOf(request: ReplyRequest): { form: URLSearchParams; query: URLSearchParams } {
  const q = request.url.indexOf('?');
  const query = new URLSearchParams(q < 0 ? '' : request.url.slice(q + 1).split('#')[0]!);
  return { form: request.method.toUpperCase() === 'POST' ? formOf(request.body) : new URLSearchParams(), query };
}

function formOf(body: ReplyRequest['body']): URLSearchParams {
  if (body === undefined || body === null) return new URLSearchParams();
  if (typeof body === 'string') return new URLSearchParams(body);
  const out = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) if (typeof v === 'string') out.set(k, v);
  return out;
}
