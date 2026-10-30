// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Verifying the identity provider's enveloped signature on a SAML 2.0 assertion. xml-crypto does the
// canonicalization and the cryptography; this file decides what is acceptable around it. In WS-Federation
// the assertion's signature is the ONLY one: the RequestSecurityTokenResponse around it is not signed,
// and the relying party signs nothing, so this module has no signing side.
//
// THE RULE AGAINST SIGNATURE WRAPPING: once a signature verifies, the element is read from the XML that
// was actually signed (xml-crypto's getSignedReferences()), never from the document it arrived in. A
// forged element placed beside the signed one is then simply not in what is read. On top of that, a
// signature is accepted only as an enveloped signature of its own parent: exactly one Reference, whose
// URI is the parent's ID, with only the enveloped and canonicalization transforms, and a document with
// two elements sharing an ID is refused before any of it.

import type { X509Certificate } from 'node:crypto';
import { SignedXml } from 'xml-crypto';
import { WsFedError } from './errors.ts';
import { NS, attr, child, children, serialize } from './xml.ts';

const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

export const SIGNATURE_ALGORITHMS: Record<string, string> = {
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'sha256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384': 'sha384',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'sha512',
};
const DIGEST_ALGORITHMS = new Set([
  'http://www.w3.org/2001/04/xmlenc#sha256',
  'http://www.w3.org/2001/04/xmldsig-more#sha384',
  'http://www.w3.org/2001/04/xmlenc#sha512',
]);
const TRANSFORMS = new Set([ENVELOPED, EXC_C14N, EXC_C14N_COMMENTS, C14N]);
const CANONICALIZATIONS = new Set([EXC_C14N, EXC_C14N_COMMENTS, C14N]);

/** Whether `el` carries an enveloped signature as a direct child. */
export function isSigned(el: Element): boolean {
  return children(el, NS.ds, 'Signature').length > 0;
}

/**
 * Verifies the enveloped signature on `el` against the identity provider's certificates, and returns
 * the XML that was signed (the element, canonicalized, without its signature). Returns undefined when
 * `el` carries no signature. Throws `signature` on any other outcome.
 *
 * @param xml  The whole document `el` is in, as text: xml-crypto verifies against the text.
 */
export function verifySigned(xml: string, el: Element, certs: readonly X509Certificate[], what: string): string | undefined {
  const sigEl = child(el, NS.ds, 'Signature');
  if (!sigEl) return undefined;
  const id = attr(el, 'ID');
  if (!id) throw new WsFedError('signature', `${what} is signed but has no ID for the signature to refer to`);

  const signedInfo = child(sigEl, NS.ds, 'SignedInfo');
  if (!signedInfo) throw new WsFedError('signature', `${what}'s signature has no SignedInfo`);
  const algorithmOf = (parent: Element, local: string) => {
    const e = child(parent, NS.ds, local);
    return e ? attr(e, 'Algorithm') ?? '' : '';
  };
  const c14n = algorithmOf(signedInfo, 'CanonicalizationMethod');
  if (!CANONICALIZATIONS.has(c14n)) throw new WsFedError('signature', `${what}'s signature uses the canonicalization ${c14n || '(none)'}, which is refused`);
  const sigAlg = algorithmOf(signedInfo, 'SignatureMethod');
  if (!SIGNATURE_ALGORITHMS[sigAlg]) throw new WsFedError('signature', `${what}'s signature uses ${sigAlg || '(none)'}, which is refused (SHA-1 and non-RSA algorithms are not accepted)`);
  const refs = children(signedInfo, NS.ds, 'Reference');
  if (refs.length !== 1) throw new WsFedError('signature', `${what}'s signature has ${refs.length} references; exactly one is accepted`);
  const ref = refs[0]!;
  if (attr(ref, 'URI') !== `#${id}`) throw new WsFedError('signature', `${what}'s signature refers to ${attr(ref, 'URI') ?? '(nothing)'}, not to ${what} itself (#${id})`);
  const digest = algorithmOf(ref, 'DigestMethod');
  if (!DIGEST_ALGORITHMS.has(digest)) throw new WsFedError('signature', `${what}'s signature digests with ${digest || '(none)'}, which is refused`);
  const transforms = child(ref, NS.ds, 'Transforms');
  for (const t of transforms ? children(transforms, NS.ds, 'Transform') : []) {
    const alg = attr(t, 'Algorithm') ?? '';
    if (!TRANSFORMS.has(alg)) throw new WsFedError('signature', `${what}'s signature uses the transform ${alg || '(none)'}, which is refused`);
  }
  if (!certs.length) throw new WsFedError('signature', `no signing certificate is known for the identity provider, so ${what} cannot be verified`);

  let reason = 'the signature does not verify';
  for (const cert of certs) {
    // getCertFromKeyInfo returns null so the certificate a message carries is never used: only the
    // identity provider's own certificates, from its metadata, are.
    const sig = new SignedXml({ publicCert: cert.toString(), getCertFromKeyInfo: () => null });
    sig.loadSignature(serialize(sigEl));
    try {
      if (sig.checkSignature(xml)) {
        const signed = sig.getSignedReferences();
        if (signed.length !== 1) throw new WsFedError('signature', `${what}'s signature covered ${signed.length} elements`);
        return signed[0]!;
      }
    } catch (err) {
      if (err instanceof WsFedError) throw err;
      reason = (err as Error).message;
    }
  }
  throw new WsFedError('signature', `${what}'s signature does not verify against the identity provider's certificate: ${reason}`);
}
