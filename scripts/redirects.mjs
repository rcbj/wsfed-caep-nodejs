// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The realm the demo registers, and the one it sends, are the same address.
// A loopback address follows the port the demo listens on. Any other host is left as written.

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1']);

/** The host, without the brackets Node keeps on an IPv6 address. */
function hostOf(url) {
  const name = url.hostname;
  return name.startsWith('[') && name.endsWith(']') ? name.slice(1, -1) : name;
}

/** Replace the port of a loopback URL. Anything else, including an unparseable value, is unchanged. */
export function onPort(url, port) {
  try {
    const next = new URL(url);
    if (!LOOPBACK.has(hostOf(next))) return url;
    next.port = String(port);
    return next.href;
  } catch {
    return url;
  }
}

/**
 * The realm and reply URL to register.
 * An explicit public URL replaces the origin and keeps each path.
 * Otherwise `port` moves a loopback address onto the port the demo listens on.
 */
export function endpointsFor(realm, replyUrl, options) {
  if (options.publicUrlGiven && options.publicUrl) {
    const base = new URL(options.publicUrl.endsWith('/') ? options.publicUrl : `${options.publicUrl}/`);
    const move = (value) => {
      const next = new URL(value);
      next.protocol = base.protocol;
      next.hostname = base.hostname;
      next.port = base.port;
      return next.href;
    };
    return { realm: move(realm), replyUrl: move(replyUrl) };
  }
  if (options.port) {
    return { realm: onPort(realm, options.port), replyUrl: onPort(replyUrl, options.port) };
  }
  return { realm, replyUrl };
}

/**
 * The container's PORT wins when it is an integer from 1 to 65535. Otherwise the environment.
 * An unusable value is absent.
 */
export function demoPort(envPort, containerPort) {
  const parse = (value) => {
    const raw = String(value ?? '').trim();
    if (!raw) return undefined;
    const port = Number(raw);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined;
    return port;
  };
  return parse(containerPort) ?? parse(envPort);
}
