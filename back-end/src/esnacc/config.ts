/**
 * Configuration of the sign-in with ESN Accounts through OAuth 2.0 (authorization code with PKCE).
 * Reference: `ESNacc_OAUTH_INTEGRATION_SPEC.md` in https://github.com/ESN-Hungary/esnscope.
 *
 * URL strategy: every URL is derived from the stage's configuration (`back-end/deploy/environments.ts`, passed to the
 * Lambda functions as environment variables); none is hardcoded and none is read from the request's headers.
 */

/**
 * The scope to request to ESN Accounts.
 */
export const SCOPE = 'oauth2_access_to_profile_information';

/**
 * The API path that starts the flow (it redirects the user to ESN Accounts).
 */
export const AUTHORIZE_PATH = '/esnacc_oauth_authorize';
/**
 * The API path where ESN Accounts redirects the user after the authorization (part of the registered redirect URI).
 */
export const CALLBACK_PATH = '/esnacc_oauth_callback';

/**
 * The cookie that keeps `state` and the PKCE verifier between the authorization request and the callback.
 * Note: it's not a session cookie; it's only used during the sign-in flow.
 */
export const OAUTH_COOKIE_NAME = 'esnacc_oauth';
/**
 * How long (in seconds) the user has to complete the sign-in on ESN Accounts.
 */
export const OAUTH_COOKIE_MAX_AGE_SECONDS = 600;

/**
 * The endpoints of ESN Accounts, derived from its base URL (e.g. `https://accounts.esn.org`).
 */
export interface ESNAccountsEndpoints {
  authorization: string;
  token: string;
  userinfo: string;
  countries: string;
  sections: string;
}
export const getESNAccountsEndpoints = (baseURL: string): ESNAccountsEndpoints => {
  const base = requireConfig(baseURL, 'ESN Accounts URL').replace(/\/+$/, '');
  return {
    authorization: base.concat('/oauth/authorize'),
    token: base.concat('/oauth/token'),
    userinfo: base.concat('/oauth/v2/userinfo'),
    countries: base.concat('/api/v2/countries'),
    sections: base.concat('/api/v2/sections')
  };
};

/**
 * The redirect URI registered with ESN Accounts, e.g. `https://api.assembly.esn.hu/dev/esnacc_oauth_callback`.
 * It must be byte-for-byte the same in the authorization and in the token requests.
 */
export const getRedirectURI = (apiDomain: string, stage: string): string =>
  `https://${requireConfig(apiDomain, 'API domain')}/${requireConfig(stage, 'stage')}${CALLBACK_PATH}`;

/**
 * The path, in AWS Systems Manager (Parameter Store), of the OAuth client's credentials (next to `/${project}/auth`).
 * The parameter is a `SecureString` containing: `{"clientId":"…","clientSecret":"…"}`.
 */
export const getClientCredentialsParameterName = (project: string): string =>
  `/${requireConfig(project, 'project')}/esnacc-oauth`;

export function requireConfig(value: string | undefined, name: string): string {
  if (!value) throw new Error(`Missing configuration: ${name}`);
  return value;
}
