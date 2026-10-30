// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

/**
 * What kind of failure a {@link WsFedError} is. An application usually answers every one of them the
 * same way (the sign-in failed, start again), and logs the code and message for the operator.
 *
 * - `config`: the configuration is incomplete or contradictory.
 * - `metadata`: the identity provider's federation metadata could not be fetched or does not describe a
 *   WS-Federation security token service that issues SAML 2.0 assertions.
 * - `message`: the request at the reply URL is not a WS-Federation sign-in response (`wa=wsignin1.0`
 *   with a `wresult`), or its `wresult` is not a RequestSecurityTokenResponse this relying party reads.
 * - `xml`: the message is not well-formed XML, or carries a DOCTYPE.
 * - `signature`: the assertion's signature is missing, uses an algorithm that is refused, or does not verify.
 * - `validation`: the assertion verified but a check on its content failed (audience, recipient, time
 *   window, issuer, `wctx`, ...).
 * - `replay`: the assertion has been accepted before.
 * - `decryption`: an encrypted assertion, NameID or attribute could not be decrypted.
 * - `ssf`: the Shared Signals transmitter could not be found, or its stream created or polled.
 */
export type WsFedErrorCode =
  | 'config'
  | 'metadata'
  | 'message'
  | 'xml'
  | 'signature'
  | 'validation'
  | 'replay'
  | 'decryption'
  | 'ssf';

/** Every failure this module reports is one of these. */
export class WsFedError extends Error {
  /** What kind of failure it is. */
  readonly code: WsFedErrorCode;

  constructor(code: WsFedErrorCode, message: string, options: { cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'WsFedError';
    this.code = code;
  }
}
