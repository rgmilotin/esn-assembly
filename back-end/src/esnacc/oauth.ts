/**
 * PKCE, `state` and the flow's cookie (as in `src/oauth.ts` of ESN-Hungary/esnscope, with a signed cookie).
 */

import { createHash, createHmac, randomBytes } from 'crypto';
import { URL } from 'url';

import { OAUTH_COOKIE_MAX_AGE_SECONDS, OAUTH_COOKIE_NAME, SCOPE } from './config';
import { OAuthRequestCookie } from './types';

//
// AUTHORIZATION REQUEST
//

/**
 * The URL of ESN Accounts' authorization endpoint, with the parameters of an authorization code flow with PKCE.
 */
export const buildAuthorizationURL = (params: {
  authorizationEndpoint: string;
  clientId: string;
  redirectURI: string;
  state: string;
  codeChallenge: string;
}): string => {
  const authorizationURL = new URL(params.authorizationEndpoint);

  authorizationURL.searchParams.set('response_type', 'code');
  authorizationURL.searchParams.set('client_id', params.clientId);
  authorizationURL.searchParams.set('redirect_uri', params.redirectURI);
  authorizationURL.searchParams.set('scope', SCOPE);
  authorizationURL.searchParams.set('state', params.state);
  authorizationURL.searchParams.set('code_challenge', params.codeChallenge);
  authorizationURL.searchParams.set('code_challenge_method', 'S256');

  return authorizationURL.toString();
};

//
// PKCE AND STATE
//

/**
 * A cryptographically random value, base64url-encoded (used for `state` and the PKCE verifier).
 */
export const randomValue = (byteLength = 32): string => base64UrlEncode(randomBytes(byteLength));

/**
 * A PKCE verifier: 64 random bytes, base64url-encoded (86 characters, within RFC 7636's 43-128).
 */
export const createCodeVerifier = (): string => randomValue(64);

/**
 * The PKCE challenge for the S256 method: base64url(SHA-256(verifier)).
 */
export const createCodeChallenge = (codeVerifier: string): string =>
  base64UrlEncode(createHash('sha256').update(codeVerifier, 'utf8').digest());

//
// FLOW COOKIE
//

/**
 * The cookie keeps `state` and the PKCE verifier between the authorization request and the callback.
 * It is HttpOnly, Secure, SameSite=Lax, limited to the callback's path, short-lived (10 minutes) and signed (HMAC).
 * The signing key is derived from the platform's secret, so the cookie can never be accepted as an API token.
 * Note: it's unrelated to the platform's session, which is the app's JWT.
 */
export const serializeOAuthCookie = (
  cookie: OAuthRequestCookie,
  secret: string,
  path: string,
  now = Date.now()
): string => {
  const payload: SignedCookiePayload = { ...cookie, exp: Math.floor(now / 1000) + OAUTH_COOKIE_MAX_AGE_SECONDS };
  const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
  const value = encodedPayload.concat('.', signCookiePayload(encodedPayload, secret));

  return OAUTH_COOKIE_NAME.concat(
    `=${value}; Max-Age=${OAUTH_COOKIE_MAX_AGE_SECONDS}; Path=${path}; HttpOnly; Secure; SameSite=Lax`
  );
};

/**
 * Get the content of the flow's cookie, if present, correctly signed and not expired; `null` otherwise.
 */
export const parseOAuthCookie = (cookies: string[], secret: string, now = Date.now()): OAuthRequestCookie | null => {
  const prefix = OAUTH_COOKIE_NAME.concat('=');
  const cookie = cookies.map(part => part.trim()).find(part => part.startsWith(prefix));
  if (!cookie) return null;

  try {
    const [encodedPayload, signature, ...rest] = cookie.slice(prefix.length).split('.');
    if (!encodedPayload || !signature || rest.length) return null;
    if (!timingSafeEqual(signature, signCookiePayload(encodedPayload, secret))) return null;

    const parsed = JSON.parse(base64UrlDecode(encodedPayload).toString('utf8')) as SignedCookiePayload;
    if (typeof parsed.state !== 'string' || typeof parsed.codeVerifier !== 'string') return null;
    if (typeof parsed.exp !== 'number' || parsed.exp * 1000 < now) return null;

    const result: OAuthRequestCookie = { state: parsed.state, codeVerifier: parsed.codeVerifier };
    if (typeof parsed.localhostPort === 'number') result.localhostPort = parsed.localhostPort;
    return result;
  } catch {
    return null;
  }
};

/**
 * The header to delete the flow's cookie (after one callback attempt, whatever the result).
 */
export const expireOAuthCookie = (path: string): string =>
  OAUTH_COOKIE_NAME.concat(`=; Max-Age=0; Path=${path}; HttpOnly; Secure; SameSite=Lax`);

/**
 * Get the request's cookies, in both the API Gateway's payload formats (2.0: `cookies`; 1.0: `Cookie` header).
 */
export const getRequestCookies = (event: any): string[] => {
  if (Array.isArray(event?.cookies)) return event.cookies;
  const header = event?.headers?.cookie ?? event?.headers?.Cookie;
  return header ? String(header).split(';') : [];
};

interface SignedCookiePayload extends OAuthRequestCookie {
  exp: number;
}

const signCookiePayload = (encodedPayload: string, secret: string): string => {
  const key = createHmac('sha256', secret).update('esnacc-oauth-cookie').digest();
  return base64UrlEncode(createHmac('sha256', key).update(encodedPayload).digest());
};

//
// HELPERS
//

export const base64UrlEncode = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const base64UrlDecode = (value: string): Buffer => Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

/**
 * Compare two strings in constant time (for equal lengths), to avoid timing attacks on `state` and signatures.
 */
export const timingSafeEqual = (left: string, right: string): boolean => {
  if (typeof left !== 'string' || typeof right !== 'string' || left.length !== right.length) return false;

  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);

  return difference === 0;
};
