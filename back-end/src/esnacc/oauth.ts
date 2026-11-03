/**
 * PKCE, state cookie and callback validation (port of `src/oauth.ts` of ESN-Hungary/esnscope).
 */

import { createHash, createHmac, randomBytes } from 'crypto';
import { URL } from 'url';

import { ENDPOINT_AUTHORIZATION, OAUTH_COOKIE_MAX_AGE_SECONDS, OAUTH_COOKIE_NAME, SCOPE } from './config';
import { HttpClient, axiosHttpClient, exchangeCodeForToken, getUserInfo } from './esnaccount';
import { OAuthRequestCookie, UserInfo } from './types';
import { ESNAccountsOAuthErrors } from '../models/esnaccOAuth.model';

/**
 * An error of the OAuth flow, with the code to report back to the front-end.
 */
export class OAuthFlowError extends Error {
  constructor(public code: ESNAccountsOAuthErrors, message: string) {
    super(message);
  }
}

//
// AUTHORIZATION REQUEST
//

export function buildAuthorizationUrl(params: {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
}): string {
  const authorizationUrl = new URL(ENDPOINT_AUTHORIZATION);

  authorizationUrl.searchParams.set('response_type', 'code');
  authorizationUrl.searchParams.set('client_id', params.clientId);
  authorizationUrl.searchParams.set('redirect_uri', params.redirectUri);
  authorizationUrl.searchParams.set('scope', SCOPE);
  authorizationUrl.searchParams.set('state', params.state);
  authorizationUrl.searchParams.set('code_challenge', params.codeChallenge);
  authorizationUrl.searchParams.set('code_challenge_method', 'S256');

  return authorizationUrl.toString();
}

//
// CALLBACK
//

/**
 * Validate the callback and get the user's profile from ESN Accounts (same order as the spec's `handleCallback`).
 * The ESN Accounts' tokens are only used here and never returned.
 */
export async function completeAuthorization(params: {
  query: Record<string, string | undefined>;
  oauthCookie: OAuthRequestCookie | null;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  http?: HttpClient;
}): Promise<UserInfo> {
  const { query, oauthCookie } = params;
  const http = params.http ?? axiosHttpClient;

  if (query.error) {
    const code =
      query.error === 'access_denied' ? ESNAccountsOAuthErrors.ACCESS_DENIED : ESNAccountsOAuthErrors.INVALID_REQUEST;
    throw new OAuthFlowError(
      code,
      `ESN Accounts returned an error: ${query.error} (${query.error_description ?? '-'})`
    );
  }

  const code = query.code;
  if (!code) throw new OAuthFlowError(ESNAccountsOAuthErrors.INVALID_REQUEST, 'No authorization code was returned.');

  const state = query.state;
  if (!oauthCookie || !state || !timingSafeEqual(state, oauthCookie.state))
    throw new OAuthFlowError(ESNAccountsOAuthErrors.INVALID_STATE, 'The OAuth state could not be verified.');

  let accessToken: string;
  try {
    const tokenResponse = await exchangeCodeForToken(
      code,
      params.clientId,
      params.clientSecret,
      oauthCookie.codeVerifier,
      params.redirectUri,
      http
    );
    accessToken = typeof tokenResponse.access_token === 'string' ? tokenResponse.access_token : null;
  } catch (error) {
    throw new OAuthFlowError(ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR, (error as Error).message);
  }
  if (!accessToken)
    throw new OAuthFlowError(
      ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR,
      'The token endpoint did not return an access token.'
    );

  try {
    return await getUserInfo(accessToken, http);
  } catch (error) {
    throw new OAuthFlowError(ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR, (error as Error).message);
  }
}

//
// STATE COOKIE
//

/**
 * The cookie keeps `state` and the PKCE verifier; it is HttpOnly, Secure, SameSite=Lax, short-lived and signed.
 * The signing key is derived from the platform's secret, so the cookie can never be accepted as an API token.
 */
export function serializeOAuthCookie(
  cookie: OAuthRequestCookie,
  secret: string,
  path: string,
  now = Date.now()
): string {
  const payload: SignedCookiePayload = { ...cookie, exp: Math.floor(now / 1000) + OAUTH_COOKIE_MAX_AGE_SECONDS };
  const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
  const value = encodedPayload.concat('.', signCookiePayload(encodedPayload, secret));

  return `${OAUTH_COOKIE_NAME}=${value}; Max-Age=${OAUTH_COOKIE_MAX_AGE_SECONDS}; Path=${path}; HttpOnly; Secure; SameSite=Lax`;
}

/**
 * Get the content of the cookie, if present, correctly signed and not expired; `null` otherwise.
 */
export function parseOAuthCookie(cookies: string[], secret: string, now = Date.now()): OAuthRequestCookie | null {
  const cookie = cookies.map(part => part.trim()).find(part => part.startsWith(OAUTH_COOKIE_NAME.concat('=')));

  if (!cookie) return null;

  try {
    const [encodedPayload, signature] = cookie.slice(OAUTH_COOKIE_NAME.length + 1).split('.');
    if (!encodedPayload || !signature) return null;
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
}

export function expireOAuthCookie(path: string): string {
  return `${OAUTH_COOKIE_NAME}=; Max-Age=0; Path=${path}; HttpOnly; Secure; SameSite=Lax`;
}

/**
 * Get the request's cookies, in both the API Gateway's payload formats (2.0: `cookies`; 1.0: `Cookie` header).
 */
export function getRequestCookies(event: any): string[] {
  if (Array.isArray(event?.cookies)) return event.cookies;
  const header = event?.headers?.cookie ?? event?.headers?.Cookie;
  return header ? String(header).split(';') : [];
}

interface SignedCookiePayload extends OAuthRequestCookie {
  exp: number;
}

const signCookiePayload = (encodedPayload: string, secret: string): string => {
  const key = createHmac('sha256', secret).update('esnacc-oauth-cookie').digest();
  return base64UrlEncode(createHmac('sha256', key).update(encodedPayload).digest());
};

//
// PKCE AND HELPERS
//

export function randomValue(byteLength = 32): string {
  return base64UrlEncode(randomBytes(byteLength));
}

export function createCodeChallenge(codeVerifier: string): string {
  return base64UrlEncode(createHash('sha256').update(codeVerifier, 'utf8').digest());
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

export function timingSafeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }

  let difference = 0;

  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }

  return difference === 0;
}
