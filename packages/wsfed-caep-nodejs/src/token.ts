// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Reading a WS-Federation sign-in response's `wresult` (WS-Federation 1.2 section 13.2.3) and validating
// the SAML 2.0 assertion it carries. The order matters:
//
//   1. the wresult: one RequestSecurityTokenResponse (WS-Trust February 2005, or WS-Trust 1.3 inside a
//      RequestSecurityTokenResponseCollection), applying to this realm, holding exactly one token;
//   2. the token: a SAML 2.0 assertion, decrypted if it is encrypted (a SAML 1.1 assertion is refused);
//   3. the assertion's own signature, REQUIRED: the response around it is never signed, so this is the
//      only proof of where it came from. From here on the assertion is read from what was signed;
//   4. the assertion: issuer, a bearer confirmation (no InResponseTo, since WS-Federation sends no
//      AuthnRequest; a Recipient, if any, that is this reply URL), the time window, this realm in the
//      audience, an authentication statement;
//   5. the assertion has not been accepted before.
//
// Nothing in the RequestSecurityTokenResponse is trusted for a decision that the signed assertion can
// make: its AppliesTo and Lifetime are checked only so that an obviously misdirected or stale response
// is refused early with a clear reason.

import type { KeyObject, X509Certificate } from 'node:crypto';
import { decryptElement } from './encryption.ts';
import { WsFedError } from './errors.ts';
import type { ReplayCache } from './replay.ts';
import { verifySigned } from './signature.ts';
import {
  CM_BEARER, NS, SAML2_TOKEN_TYPES, assertUniqueIds, attr, child, children, elementChildren, is, parseXml, text, wsaAddresses,
} from './xml.ts';

/** Who signed in, as the identity provider asserted it. */
export interface WsFedLogin {
  /** The subject's NameID value. */
  nameId: string;
  /** Its Format, e.g. `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`. */
  nameIdFormat?: string;
  nameQualifier?: string;
  spNameQualifier?: string;
  /** The identity provider's session: the AuthnStatement's SessionIndex. A CAEP event names it. */
  sessionIndex?: string;
  /** When the identity provider says this session must end, if it says. */
  sessionNotOnOrAfter?: Date;
  /** When the person authenticated. */
  authnInstant: Date;
  /** How, e.g. `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`. */
  authnContextClassRef?: string;
  /** Every attribute, by its Name, with all its values. WS-Federation identity providers name them with claim URIs. */
  attributes: Record<string, string[]>;
  /** The FriendlyName of each attribute that has one, by Name. */
  attributeFriendlyNames: Record<string, string>;
  /** The identity provider's entityID. */
  issuer: string;
  /** The realm the assertion was issued to (its audience). */
  realm: string;
  /** The id of the sign-in request this answers, from `wctx`; absent for an unsolicited response. */
  requestId?: string;
  /** The application state that came back in `wctx` (the `relayState` given to `login()`). */
  relayState?: string;
  /** The WS-Trust version of the response that carried the token. */
  trustVersion: '2005/02' | '1.3';
  /** Whether the assertion arrived encrypted. */
  encrypted: boolean;
  assertionId: string;
  /** When the assertion's bearer confirmation expires. */
  notOnOrAfter: Date;
}

export interface ValidationContext {
  realm: string;
  replyUrl: string;
  idpEntityId: string;
  idpCertificates: readonly X509Certificate[];
  decryptionKey: KeyObject | undefined;
  clockSkewMs: number;
  wantAssertionsEncrypted: boolean;
  replayCache: ReplayCache;
  now?: Date;
}

/** What validateToken reads from the wresult: everything but the wctx correlation. */
export type ValidatedToken = Omit<WsFedLogin, 'requestId' | 'relayState'>;

const invalid = (message: string): never => {
  throw new WsFedError('validation', message);
};
const malformed = (message: string): never => {
  throw new WsFedError('message', message);
};

function instant(value: string | undefined, what: string): Date | undefined {
  if (value === undefined) return undefined;
  // xs:dateTime as SAML and WS-Security use it: UTC, with a Z.
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(value)) return invalid(`${what} is not a UTC dateTime: ${value}`);
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? invalid(`${what} is not a dateTime: ${value}`) : d;
}

/** The one RequestSecurityTokenResponse in a wresult, and the WS-Trust namespace it is in. */
function responseOf(root: Element): { rstr: Element; trust: string; trustVersion: WsFedLogin['trustVersion'] } {
  if (is(root, NS.trust13, 'RequestSecurityTokenResponseCollection')) {
    const all = children(root, NS.trust13, 'RequestSecurityTokenResponse');
    if (all.length !== 1) malformed(`the RequestSecurityTokenResponseCollection holds ${all.length} responses; exactly one is accepted`);
    return { rstr: all[0]!, trust: NS.trust13, trustVersion: '1.3' };
  }
  if (is(root, NS.trust2005, 'RequestSecurityTokenResponse')) return { rstr: root, trust: NS.trust2005, trustVersion: '2005/02' };
  if (is(root, NS.trust13, 'RequestSecurityTokenResponse')) return { rstr: root, trust: NS.trust13, trustVersion: '1.3' };
  return malformed(`wresult is a <${root.localName}> in ${root.namespaceURI ?? 'no namespace'}, not a WS-Trust RequestSecurityTokenResponse`);
}

/**
 * Validates a sign-in response's `wresult` and returns who signed in. Throws a {@link WsFedError}
 * otherwise. The `wctx` correlation is the caller's (the relying party checks it before this).
 */
export async function validateToken(wresult: string, ctx: ValidationContext): Promise<ValidatedToken> {
  const now = (ctx.now ?? new Date()).getTime();
  const skew = ctx.clockSkewMs;

  // 1. The RequestSecurityTokenResponse.
  const doc = parseXml(wresult, 'wresult');
  assertUniqueIds(doc);
  const { rstr, trust, trustVersion } = responseOf(doc.documentElement);
  const tokenType = text(child(rstr, trust, 'TokenType'));
  if (tokenType && !SAML2_TOKEN_TYPES.includes(tokenType)) {
    malformed(`the response carries a token of type ${tokenType}; this relying party accepts SAML 2.0 assertions only`);
  }
  const appliesTo = [...children(rstr, NS.wsp, 'AppliesTo'), ...children(rstr, NS.wsp15, 'AppliesTo')];
  if (appliesTo.length > 1) malformed('the response has more than one AppliesTo');
  if (appliesTo[0]) {
    const scopes = wsaAddresses(appliesTo[0]);
    if (scopes.length && !scopes.includes(ctx.realm)) invalid(`the response applies to ${scopes.join(', ')}, not to ${ctx.realm}`);
  }
  const lifetime = child(rstr, trust, 'Lifetime');
  const expires = lifetime ? instant(text(child(lifetime, NS.wsu, 'Expires')) || undefined, 'the response\'s Lifetime Expires') : undefined;
  if (expires && expires.getTime() <= now - skew) invalid(`the response expired at ${expires.toISOString()}`);

  const requested = children(rstr, trust, 'RequestedSecurityToken');
  if (requested.length !== 1) malformed(`the response holds ${requested.length} RequestedSecurityToken elements; exactly one is accepted`);
  const tokens = elementChildren(requested[0]!);
  if (tokens.length !== 1) malformed(`the RequestedSecurityToken holds ${tokens.length} tokens; exactly one is accepted`);
  const token = tokens[0]!;

  // 2. The token: a SAML 2.0 assertion, decrypted if it is encrypted.
  let assertion: Element;
  let assertionXml: string;
  let encrypted = false;
  if (is(token, NS.saml, 'Assertion')) {
    if (ctx.wantAssertionsEncrypted) invalid('the assertion is not encrypted, and wantAssertionsEncrypted is on');
    assertion = token;
    assertionXml = wresult;
  } else if (is(token, NS.saml, 'EncryptedAssertion') || is(token, NS.xenc, 'EncryptedData')) {
    if (!ctx.decryptionKey) throw new WsFedError('decryption', 'the assertion is encrypted, and this relying party has no privateKey to decrypt it with');
    encrypted = true;
    assertionXml = decryptElement(token, ctx.decryptionKey);
    const decrypted = parseXml(assertionXml, 'the decrypted assertion');
    assertUniqueIds(decrypted);
    assertion = decrypted.documentElement;
    if (is(assertion, NS.saml1, 'Assertion')) {
      malformed('the encrypted token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only');
    }
    if (!is(assertion, NS.saml, 'Assertion')) invalid('the encrypted token does not hold a SAML 2.0 Assertion');
  } else if (is(token, NS.saml1, 'Assertion')) {
    return malformed('the token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only. '
      + 'Ask for SAML 2.0 (requestTokenType, the default), or configure the identity provider to issue it to this realm');
  } else {
    return malformed(`the RequestedSecurityToken holds a <${token.localName}>, not a SAML 2.0 assertion`);
  }

  // 3. The assertion's signature, and from here on the assertion as signed.
  const signedAssertion = verifySigned(assertionXml, assertion, ctx.idpCertificates, 'the assertion');
  if (signedAssertion === undefined) {
    invalid('the assertion is not signed; in WS-Federation its signature is the only one, so it is required');
  }
  assertion = parseXml(signedAssertion!, 'the signed assertion').documentElement;

  // 4. The assertion.
  if (attr(assertion, 'Version') !== '2.0') invalid('the assertion is not version 2.0');
  const assertionId = attr(assertion, 'ID') ?? invalid('the assertion has no ID');
  const issuer = child(assertion, NS.saml, 'Issuer') ?? invalid('the assertion has no Issuer');
  const issuerFormat = attr(issuer, 'Format');
  if (issuerFormat && issuerFormat !== 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity') invalid(`the assertion's Issuer has the Format ${issuerFormat}`);
  if (text(issuer) !== ctx.idpEntityId) invalid(`the assertion was issued by ${text(issuer)}, not by ${ctx.idpEntityId}`);

  const subject = child(assertion, NS.saml, 'Subject') ?? invalid('the assertion has no Subject');
  let nameIdEl = child(subject, NS.saml, 'NameID');
  const encryptedId = child(subject, NS.saml, 'EncryptedID');
  if (!nameIdEl && encryptedId) {
    if (!ctx.decryptionKey) throw new WsFedError('decryption', 'the NameID is encrypted, and this relying party has no privateKey to decrypt it with');
    nameIdEl = parseXml(decryptElement(encryptedId, ctx.decryptionKey), 'the decrypted NameID').documentElement;
    if (!is(nameIdEl, NS.saml, 'NameID')) invalid('the EncryptedID does not hold a NameID');
  }
  if (!nameIdEl || !text(nameIdEl)) invalid('the assertion\'s Subject has no NameID');

  const conditions = child(assertion, NS.saml, 'Conditions') ?? invalid('the assertion has no Conditions, so it names no audience');
  const notBefore = instant(attr(conditions, 'NotBefore'), 'Conditions NotBefore');
  const notOnOrAfter = instant(attr(conditions, 'NotOnOrAfter'), 'Conditions NotOnOrAfter');

  // A bearer SubjectConfirmation, unexpired. There was no AuthnRequest, so one that answers a request
  // (InResponseTo) belongs to a SAML Web SSO exchange, not to this one, and is not accepted here; a
  // Recipient, when the identity provider names one, must be this reply URL.
  //
  // SubjectConfirmationData is optional (SAML Core 2.4.1.1); only the Web Browser SSO profile requires
  // it, and WS-Federation does not use that profile. Identity providers issuing a SAML 2.0 token to a
  // WS-Federation relying party (iya-sts among them) send a bare bearer confirmation, whose lifetime is
  // then the Conditions' NotOnOrAfter. One without that is refused: nothing would bound the assertion.
  const reasons: string[] = [];
  let confirmedUntil: Date | undefined;
  for (const sc of children(subject, NS.saml, 'SubjectConfirmation')) {
    if (attr(sc, 'Method') !== CM_BEARER) {
      reasons.push(`method ${attr(sc, 'Method')}`);
      continue;
    }
    const data = child(sc, NS.saml, 'SubjectConfirmationData');
    if (!data) {
      if (!notOnOrAfter) {
        reasons.push('no SubjectConfirmationData, and no Conditions NotOnOrAfter to bound it');
        continue;
      }
      confirmedUntil = notOnOrAfter;
      break;
    }
    const recipient = attr(data, 'Recipient');
    const until = instant(attr(data, 'NotOnOrAfter'), 'SubjectConfirmationData NotOnOrAfter') ?? notOnOrAfter;
    if (recipient !== undefined && recipient !== ctx.replyUrl) reasons.push(`Recipient ${recipient}`);
    else if (!until) reasons.push('no NotOnOrAfter, on the confirmation or the Conditions');
    else if (until.getTime() <= now - skew) reasons.push(`expired at ${until.toISOString()}`);
    else if (attr(data, 'NotBefore') !== undefined) reasons.push('a NotBefore, which a bearer confirmation must not have');
    else if (attr(data, 'InResponseTo') !== undefined) reasons.push(`InResponseTo ${attr(data, 'InResponseTo')}, which answers a SAML request, not a WS-Federation sign-in`);
    else {
      confirmedUntil = until;
      break;
    }
  }
  if (!confirmedUntil) invalid(`no bearer SubjectConfirmation of the assertion fits: ${reasons.join('; ') || 'there is none'}`);

  if (notBefore && notBefore.getTime() > now + skew) invalid(`the assertion is not valid before ${notBefore.toISOString()}`);
  if (notOnOrAfter && notOnOrAfter.getTime() <= now - skew) invalid(`the assertion expired at ${notOnOrAfter.toISOString()}`);
  const restrictions = children(conditions, NS.saml, 'AudienceRestriction');
  if (!restrictions.length) invalid('the assertion has no AudienceRestriction');
  // Every AudienceRestriction must name this realm (SAML Core 2.5.1.4).
  for (const r of restrictions) {
    if (!children(r, NS.saml, 'Audience').some((a) => text(a) === ctx.realm)) invalid(`the assertion is not for ${ctx.realm}`);
  }

  const authn = children(assertion, NS.saml, 'AuthnStatement')[0] ?? invalid('the assertion has no AuthnStatement');
  const authnInstant = instant(attr(authn, 'AuthnInstant'), 'AuthnInstant') ?? invalid('the AuthnStatement has no AuthnInstant');
  const sessionNotOnOrAfter = instant(attr(authn, 'SessionNotOnOrAfter'), 'SessionNotOnOrAfter');
  if (sessionNotOnOrAfter && sessionNotOnOrAfter.getTime() <= now - skew) invalid('the identity provider\'s session has already ended');
  const contextEl = child(authn, NS.saml, 'AuthnContext');
  const classRef = contextEl ? text(child(contextEl, NS.saml, 'AuthnContextClassRef')) : '';

  const attributes: Record<string, string[]> = {};
  const attributeFriendlyNames: Record<string, string> = {};
  for (const statement of children(assertion, NS.saml, 'AttributeStatement')) {
    // An EncryptedAttribute (SAML Core 2.7.3.2) is decrypted to the Attribute it holds; the assertion's
    // signature covers its ciphertext, so it was verified above like everything else.
    const decrypted = children(statement, NS.saml, 'EncryptedAttribute').map((e) => {
      if (!ctx.decryptionKey) throw new WsFedError('decryption', 'an attribute is encrypted, and this relying party has no privateKey to decrypt it with');
      const el = parseXml(decryptElement(e, ctx.decryptionKey), 'the decrypted attribute').documentElement;
      if (!is(el, NS.saml, 'Attribute')) invalid('an EncryptedAttribute does not hold an Attribute');
      return el;
    });
    for (const a of [...children(statement, NS.saml, 'Attribute'), ...decrypted]) {
      const name = attr(a, 'Name');
      if (!name) continue;
      const values = children(a, NS.saml, 'AttributeValue').map((v) => v.textContent ?? '');
      (attributes[name] ??= []).push(...values);
      const friendly = attr(a, 'FriendlyName');
      if (friendly) attributeFriendlyNames[name] = friendly;
    }
  }

  // 5. Once only. Remembered for as long as the assertion could be presented.
  const keepUntil = new Date(Math.max(confirmedUntil!.getTime(), notOnOrAfter?.getTime() ?? 0) + skew);
  if (await ctx.replayCache.checkAndRecord(`${ctx.idpEntityId} ${assertionId}`, keepUntil)) {
    throw new WsFedError('replay', `the assertion ${assertionId} has been accepted before`);
  }

  const login: ValidatedToken = {
    nameId: text(nameIdEl),
    authnInstant,
    attributes,
    attributeFriendlyNames,
    issuer: ctx.idpEntityId,
    realm: ctx.realm,
    trustVersion,
    encrypted,
    assertionId,
    notOnOrAfter: confirmedUntil!,
  };
  const optional: Partial<ValidatedToken> = {
    nameIdFormat: attr(nameIdEl!, 'Format'),
    nameQualifier: attr(nameIdEl!, 'NameQualifier'),
    spNameQualifier: attr(nameIdEl!, 'SPNameQualifier'),
    sessionIndex: attr(authn, 'SessionIndex'),
    sessionNotOnOrAfter,
    authnContextClassRef: classRef || undefined,
  };
  for (const [k, v] of Object.entries(optional)) if (v !== undefined) (login as unknown as Record<string, unknown>)[k] = v;
  return login;
}
