/**
 * Configuration of the OAuth 2.0 client for ESN Accounts.
 * Reference: `ESNacc_OAUTH_INTEGRATION_SPEC.md` in https://github.com/ESN-Hungary/esnscope.
 */

export const ESN_ACCOUNTS_URL = 'https://accounts.esn.org';
export const SCOPE = 'oauth2_access_to_profile_information';
export const ENDPOINT_AUTHORIZATION = ESN_ACCOUNTS_URL.concat('/oauth/authorize');
export const ENDPOINT_TOKEN = ESN_ACCOUNTS_URL.concat('/oauth/token');
export const ENDPOINT_USERINFO = ESN_ACCOUNTS_URL.concat('/oauth/v2/userinfo');

/**
 * The API path where ESN Accounts redirects the user after the authorization (part of the registered redirect URI).
 */
export const CALLBACK_PATH = '/esnacc_oauth_callback';

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
