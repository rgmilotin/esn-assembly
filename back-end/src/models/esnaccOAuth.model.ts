/**
 * The API path (relative to the API stage) that starts the sign-in with ESN Accounts through OAuth 2.0.
 */
export const ESNACC_OAUTH_AUTHORIZE_PATH = '/esnacc_oauth_authorize';
/**
 * The API path (relative to the API stage) where ESN Accounts redirects the user after the OAuth 2.0 authorization.
 * It's part of the redirect URI registered with ESN Accounts.
 */
export const ESNACC_OAUTH_CALLBACK_PATH = '/esnacc_oauth_callback';

/**
 * The errors of the sign-in with ESN Accounts through OAuth 2.0, as reported back to the front-end.
 */
export enum ESNAccountsOAuthErrors {
  /**
   * The user denied the access (or cancelled the sign-in) on ESN Accounts.
   */
  ACCESS_DENIED = 'access_denied',
  /**
   * ESN Accounts redirected back without the expected parameters, or with an error.
   */
  INVALID_REQUEST = 'invalid_request',
  /**
   * The `state` of the flow is missing, expired or doesn't match: the flow must restart.
   */
  INVALID_STATE = 'invalid_state',
  /**
   * The token or userinfo endpoint of ESN Accounts failed.
   */
  ESN_ACCOUNTS_ERROR = 'esnacc_error',
  /**
   * The ESN Accounts profile has no legacy (CAS) username, so it can't be linked to the platform's users.
   */
  NO_LEGACY_ID = 'no_legacy_id',
  /**
   * Any other error.
   */
  GENERIC = 'generic'
}
