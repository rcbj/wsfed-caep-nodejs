// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Federation metadata, both ways (WS-Federation 1.2 section 3: the SAML 2.0 metadata format, with roles
// of its own as `md:RoleDescriptor xsi:type=...`):
//
//   reading the identity provider's: its entityID, the PassiveRequestorEndpoint of its
//     fed:SecurityTokenServiceType role (where wsignin1.0 goes), the token types it offers, and the
//     certificates it signs with;
//   writing this relying party's own, a fed:ApplicationServiceType role: its realm, its reply URL, and
//     the key an identity provider may encrypt assertions to.

import { X509Certificate } from 'node:crypto';
import { WsFedError } from './errors.ts';
import { NS, SAML2_TOKEN_TYPES, attr, children, descendants, escapeXml, is, parseXml, pemBody, text, toPem, wsaAddresses, xsiType } from './xml.ts';

/** What this module needs to know about the identity provider. */
export interface IdpMetadata {
  entityId: string;
  /** The PassiveRequestorEndpoint: where the browser is sent with `wa=wsignin1.0` and `wa=wsignout1.0`. */
  passiveRequestorEndpoint: string;
  /** The token type URIs the security token service offers (`fed:TokenTypesOffered`); empty when it does not say. */
  tokenTypesOffered: string[];
  /** The certificates its assertion signatures are verified against. */
  signingCertificates: X509Certificate[];
}

const isStsRole = (el: Element) => {
  if (!is(el, NS.md, 'RoleDescriptor')) return false;
  const type = xsiType(el);
  return type?.ns === NS.fed && type.local === 'SecurityTokenServiceType';
};

function certificatesOf(role: Element, use: 'signing' | 'encryption'): X509Certificate[] {
  const out: X509Certificate[] = [];
  for (const kd of children(role, NS.md, 'KeyDescriptor')) {
    const u = attr(kd, 'use');
    if (u && u !== use) continue;
    // The first certificate of each X509Data is the key's own; any after it are its chain.
    for (const data of descendants(kd, NS.ds, 'X509Data')) {
      const first = children(data, NS.ds, 'X509Certificate')[0];
      if (!first) continue;
      try {
        out.push(new X509Certificate(toPem(text(first))));
      } catch (err) {
        throw new WsFedError('metadata', `a ${use} certificate in the identity provider's metadata cannot be read`, { cause: err });
      }
    }
  }
  return out;
}

/** The `wsa:Address` of each `wsa:EndpointReference` inside `el`'s children named `local`. */
function addresses(role: Element, local: string): string[] {
  return children(role, NS.fed, local).flatMap(wsaAddresses);
}

/**
 * Reads WS-Federation identity provider metadata: an EntityDescriptor, or an EntitiesDescriptor holding
 * the one named `entityId`, with a `fed:SecurityTokenServiceType` RoleDescriptor.
 *
 * The signing certificates are the security token service role's own. An entity that publishes them only
 * on its IDPSSODescriptor (the same entity's SAML 2.0 identity provider role, with the same signer) has
 * them read from there.
 */
export function readIdpMetadata(xml: string, entityId?: string): IdpMetadata {
  const doc = parseXml(xml, 'the identity provider metadata');
  const root = doc.documentElement;
  const hasSts = (e: Element) => children(e, NS.md, 'RoleDescriptor').some(isStsRole);
  let entity: Element | undefined;
  if (is(root, NS.md, 'EntityDescriptor')) {
    entity = root;
  } else if (is(root, NS.md, 'EntitiesDescriptor')) {
    const all = descendants(root, NS.md, 'EntityDescriptor').filter(hasSts);
    entity = entityId ? all.find((e) => attr(e, 'entityID') === entityId) : all.length === 1 ? all[0] : undefined;
    if (!entity) {
      throw new WsFedError('metadata', entityId
        ? `the metadata aggregate has no WS-Federation identity provider ${entityId}`
        : `the metadata aggregate holds ${all.length} WS-Federation identity providers; name one with idpEntityId`);
    }
  } else {
    throw new WsFedError('metadata', 'the identity provider metadata is not an EntityDescriptor');
  }
  const id = attr(entity, 'entityID');
  if (!id) throw new WsFedError('metadata', 'the identity provider metadata has no entityID');
  if (entityId && id !== entityId) throw new WsFedError('metadata', `the metadata describes ${id}, not ${entityId}`);
  const role = children(entity, NS.md, 'RoleDescriptor').find(isStsRole);
  if (!role) throw new WsFedError('metadata', `${id}'s metadata has no fed:SecurityTokenServiceType RoleDescriptor, so it is not a WS-Federation identity provider`);

  const passive = addresses(role, 'PassiveRequestorEndpoint')[0];
  if (!passive) throw new WsFedError('metadata', `${id}'s metadata names no PassiveRequestorEndpoint`);
  try {
    const u = new URL(passive);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('not http(s)');
  } catch {
    throw new WsFedError('metadata', `${id}'s PassiveRequestorEndpoint ${passive} is not an http(s) URL`);
  }

  const tokenTypesOffered = children(role, NS.fed, 'TokenTypesOffered')
    .flatMap((t) => children(t, NS.fed, 'TokenType')).map((t) => attr(t, 'Uri') ?? '').filter(Boolean);
  if (tokenTypesOffered.length && !tokenTypesOffered.some((t) => SAML2_TOKEN_TYPES.includes(t))) {
    throw new WsFedError('metadata', `${id} offers no SAML 2.0 token (it offers ${tokenTypesOffered.join(', ')})`);
  }

  let signingCertificates = certificatesOf(role, 'signing');
  if (!signingCertificates.length) {
    const idp = children(entity, NS.md, 'IDPSSODescriptor')[0];
    if (idp) signingCertificates = certificatesOf(idp, 'signing');
  }
  if (!signingCertificates.length) throw new WsFedError('metadata', `${id}'s metadata names no signing certificate`);
  return { entityId: id, passiveRequestorEndpoint: passive, tokenTypesOffered, signingCertificates };
}

const ENCRYPTION_METHODS = [
  'http://www.w3.org/2009/xmlenc11#aes256-gcm',
  'http://www.w3.org/2009/xmlenc11#aes128-gcm',
  'http://www.w3.org/2009/xmlenc11#rsa-oaep',
  'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
];

/** What goes into this relying party's metadata. */
export interface RpMetadataInput {
  realm: string;
  replyUrl: string;
  /** The encryption certificate, when the relying party has a key pair. */
  certificate?: X509Certificate;
}

const endpoint = (local: string, address: string) =>
  `    <fed:${local}><wsa:EndpointReference><wsa:Address>${escapeXml(address)}</wsa:Address></wsa:EndpointReference></fed:${local}>`;

/**
 * This relying party's federation metadata: a `fed:ApplicationServiceType` role naming its realm
 * (TargetScopes), its reply URL (where tokens are posted, and where `wsignoutcleanup1.0` is sent), the
 * SAML 2.0 token type it accepts, and, with a key pair, the certificate assertions may be encrypted to.
 */
export function writeRpMetadata(input: RpMetadataInput): string {
  // The encryption key names what this relying party decrypts, strongest first (SAML Metadata 2.4.1.1):
  // an identity provider that reads them picks from these, and never PKCS#1 v1.5.
  const key = input.certificate
    ? `    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>${pemBody(input.certificate.toString())}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>${ENCRYPTION_METHODS.map((m) => `\n      <md:EncryptionMethod Algorithm="${m}"/>`).join('')}
    </md:KeyDescriptor>
`
    : '';
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="${NS.md}" xmlns:ds="${NS.ds}" xmlns:fed="${NS.fed}" xmlns:wsa="${NS.wsa}" xmlns:xsi="${NS.xsi}" entityID="${escapeXml(input.realm)}">
  <md:RoleDescriptor xsi:type="fed:ApplicationServiceType" protocolSupportEnumeration="${NS.fed}">
${key}    <fed:TokenTypesOffered><fed:TokenType Uri="${SAML2_TOKEN_TYPES[0]}"/></fed:TokenTypesOffered>
    <fed:TargetScopes><wsa:EndpointReference><wsa:Address>${escapeXml(input.realm)}</wsa:Address></wsa:EndpointReference></fed:TargetScopes>
${endpoint('ApplicationServiceEndpoint', input.replyUrl)}
${endpoint('SingleSignOutNotificationEndpoint', input.replyUrl)}
${endpoint('PassiveRequestorEndpoint', input.replyUrl)}
  </md:RoleDescriptor>
</md:EntityDescriptor>
`;
}
