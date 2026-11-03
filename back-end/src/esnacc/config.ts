/**
 * Configuration of the OAuth 2.0 client for ESN Accounts.
 * Reference: `ESNacc_OAUTH_INTEGRATION_SPEC.md` in https://github.com/ESN-Hungary/esnscope.
 */

import { ESNACC_OAUTH_CALLBACK_PATH } from '../models/esnaccOAuth.model';

export const SCOPE = 'oauth2_access_to_profile_information';
export const ENDPOINT_AUTHORIZATION = 'https://accounts.esn.org/oauth/authorize';
export const ENDPOINT_TOKEN = 'https://accounts.esn.org/oauth/token';
export const ENDPOINT_USERINFO = 'https://accounts.esn.org/oauth/v2/userinfo';

/**
 * The cookie that keeps `state` and the PKCE verifier between the authorization request and the callback.
 */
export const OAUTH_COOKIE_NAME = 'esnacc_oauth';
/**
 * How long the user has to complete the sign-in on ESN Accounts.
 */
export const OAUTH_COOKIE_MAX_AGE_SECONDS = 600;

export function requireConfig(value: string | undefined, name: string): string {
  if (!value) throw new Error(`Missing configuration: ${name}`);
  return value;
}

/**
 * The path, in AWS Systems Manager (Parameter Store), of the OAuth client's credentials.
 * The parameter is a `SecureString` containing: `{"clientId":"…","clientSecret":"…"}`.
 */
export function getClientCredentialsParameterName(project: string): string {
  return `/${project}/esnacc-oauth`;
}

/**
 * The redirect URI registered with ESN Accounts.
 * It is fixed for each stage and never derived from the request's headers.
 */
export function getRedirectUri(apiDomain: string, stage: string): string {
  return `https://${apiDomain.replace(/\/+$/, '')}/${stage}${ESNACC_OAUTH_CALLBACK_PATH}`;
}

/**
 * The cookie is sent by the browser only to the callback.
 */
export function getCookiePath(stage: string): string {
  return `/${stage}${ESNACC_OAUTH_CALLBACK_PATH}`;
}
