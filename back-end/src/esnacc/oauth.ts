/**
 * PKCE, `state`, the flow's cookie and the callback's validation (as in `src/oauth.ts` of ESN-Hungary/esnscope, with
 * a signed cookie).
 */

import { createHash, createHmac, randomBytes } from 'crypto';
import { URL } from 'url';

import { OAUTH_COOKIE_MAX_AGE_SECONDS, OAUTH_COOKIE_NAME, SCOPE } from './config';
import { HttpClient, exchangeCodeForToken, getUserInfo } from './esnaccount';
import { OAuthRequestCookie, UserInfo } from './types';
import { ESNAccountsOAuthErrors } from '../models/esnaccOAuth.model';

/**
 * An error of the OAuth flow, with the code to report back to the front-end.
 * Note: the message is only for the logs and never contains tokens or secrets.
 */
export class OAuthFlowError extends Error {
  constructor(
    public code: ESNAccountsOAuthErrors,
    message: string
  ) {
    super(message);
  }
}

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
// CALLBACK
//

/**
 * Validate the callback and get the user's profile from ESN Accounts (same order as the spec's `handleCallback`):
 * provider's error, authorization code, state (against the flow's cookie), token exchange, userinfo.
 * The ESN Accounts' tokens are only used here and never returned nor logged.
 */
export const completeAuthorization = async (params: {
  query: Record<string, string | undefined>;
  oauthCookie: OAuthRequestCookie | null;
  tokenEndpoint: string;
  userinfoEndpoint: string;
  clientId: string;
  clientSecret: string;
  redirectURI: string;
  http?: HttpClient;
}): Promise<UserInfo> => {
  const query = params.query ?? {};
  const { oauthCookie, http } = params;

  if (query.error) {
    const code =
      query.error === 'access_denied' ? ESNAccountsOAuthErrors.ACCESS_DENIED : ESNAccountsOAuthErrors.INVALID_REQUEST;
    throw new OAuthFlowError(
      code,
      `ESN Accounts returned an error: ${String(query.error)
        .replace(/[^\w.-]/g, '')
        .slice(0, 64)}`
    );
  }

  const code = query.code;
  if (!code) throw new OAuthFlowError(ESNAccountsOAuthErrors.INVALID_REQUEST, 'No authorization code was returned');

  if (!oauthCookie || !query.state || !timingSafeEqual(query.state, oauthCookie.state))
    throw new OAuthFlowError(ESNAccountsOAuthErrors.INVALID_STATE, 'The OAuth state could not be verified');

  let accessToken: string;
  try {
    const tokenResponse = await exchangeCodeForToken({
      tokenEndpoint: params.tokenEndpoint,
      code,
      clientId: params.clientId,
      clientSecret: params.clientSecret,
      codeVerifier: oauthCookie.codeVerifier,
      redirectURI: params.redirectURI,
      http
    });
    accessToken = typeof tokenResponse.access_token === 'string' ? tokenResponse.access_token : null;
  } catch (error) {
    throw new OAuthFlowError(ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR, (error as Error).message);
  }
  if (!accessToken)
    throw new OAuthFlowError(ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR, 'The token endpoint returned no access token');

  try {
    return await getUserInfo({ userinfoEndpoint: params.userinfoEndpoint, accessToken, http });
  } catch (error) {
    throw new OAuthFlowError(ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR, (error as Error).message);
  }
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
