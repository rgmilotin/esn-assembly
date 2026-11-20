///
/// IMPORTS
///

import { ResourceController, SystemsManager } from 'idea-aws';

import {
  AUTHORIZE_PATH,
  getClientCredentialsParameterName,
  getESNAccountsEndpoints,
  getRedirectURI,
  requireConfig
} from '../esnacc/config';
import {
  buildAuthorizationURL,
  createCodeChallenge,
  createCodeVerifier,
  randomValue,
  serializeOAuthCookie
} from '../esnacc/oauth';
import { OAuthRequestCookie } from '../esnacc/types';

import { ESNAccountsOAuthErrors } from '../models/esnaccOAuth.model';

///
/// CONSTANTS, ENVIRONMENT VARIABLES, HANDLER
///

const PROJECT = process.env.PROJECT;
const STAGE = process.env.STAGE;
const APP_DOMAIN = process.env.APP_DOMAIN;
const API_DOMAIN = process.env.API_DOMAIN;
const ESN_ACCOUNTS_URL = process.env.ESN_ACCOUNTS_URL;

const SECRETS_PATH = `/${PROJECT}/auth`;
const systemsManager = new SystemsManager();

let JWT_SECRET: string;
let CLIENT_CREDENTIALS: { clientId: string; clientSecret: string };

export const handler = (ev: any, _: any, cb: any): Promise<void> => new ESNAccountsOAuth(ev, cb).handleRequest();

///
/// RESOURCE CONTROLLER
///

/**
 * Sign-in with ESN Accounts through OAuth 2.0 (authorization code + PKCE), alongside the CAS login (`login.ts`).
 * All the URLs are derived from the stage's configuration (see `esnacc/config.ts`).
 */
class ESNAccountsOAuth extends ResourceController {
  constructor(event: any, callback: any) {
    super(event, callback);
    this.callback = callback;
  }

  protected async getResources(): Promise<any> {
    if (this.resourcePath.endsWith(AUTHORIZE_PATH)) await this.startAuthorization();
  }

  /**
   * Redirect the user to ESN Accounts, keeping the flow's `state` and PKCE verifier in a short-lived signed cookie.
   */
  private async startAuthorization(): Promise<void> {
    const localhostPort = parseLocalhostPort(this.queryParams.localhost);
    try {
      const endpoints = getESNAccountsEndpoints(ESN_ACCOUNTS_URL);
      const redirectURI = getRedirectURI(API_DOMAIN, STAGE);
      const { clientId } = await getClientCredentials();

      const state = randomValue();
      const codeVerifier = createCodeVerifier();
      const authorizationURL = buildAuthorizationURL({
        authorizationEndpoint: endpoints.authorization,
        clientId,
        redirectURI,
        state,
        codeChallenge: createCodeChallenge(codeVerifier)
      });

      const oauthCookie: OAuthRequestCookie = { state, codeVerifier };
      if (localhostPort) oauthCookie.localhostPort = localhostPort;
      const secret = await getJwtSecretFromSystemsManager();
      const cookie = serializeOAuthCookie(oauthCookie, secret, getCookiePath());

      this.redirect(authorizationURL, [cookie]);
    } catch (err) {
      this.logger.error('ESN ACCOUNTS OAUTH: START', err);
      this.redirect(getAuthPageURL(localhostPort, { error: ESNAccountsOAuthErrors.GENERIC }), []);
    }
  }

  private redirect(location: string, cookies: string[]): void {
    this.callback(null, { statusCode: 302, headers: { Location: location, 'Cache-Control': 'no-store' }, cookies });
  }

  /**
   * The query parameters of the OAuth flow (authorization code and state) are never logged.
   */
  protected getEventSummary(): Record<string, any> {
    const summary = super.getEventSummary();
    const queryParams = { ...(summary.queryParams ?? {}) };
    for (const param of ['code', 'state']) if (queryParams[param]) queryParams[param] = '[REDACTED]';
    return { ...summary, queryParams };
  }
}

///
/// HELPERS
///

const getJwtSecretFromSystemsManager = async (): Promise<string> => {
  if (!JWT_SECRET) JWT_SECRET = await systemsManager.getSecretByName(SECRETS_PATH);
  return JWT_SECRET;
};

/**
 * The OAuth client's credentials, from AWS Systems Manager (Parameter Store); cached for the Lambda's lifetime.
 */
const getClientCredentials = async (): Promise<{ clientId: string; clientSecret: string }> => {
  if (!CLIENT_CREDENTIALS) {
    const parameter = await systemsManager.getSecretByName(getClientCredentialsParameterName(PROJECT));
    let clientId: string, clientSecret: string;
    try {
      ({ clientId, clientSecret } = JSON.parse(parameter));
    } catch {
      // note: the parsing error isn't forwarded, since it could quote the secret
      throw new Error('The OAuth client credentials are not valid JSON');
    }
    CLIENT_CREDENTIALS = {
      clientId: requireConfig(clientId, 'clientId'),
      clientSecret: requireConfig(clientSecret, 'clientSecret')
    };
  }
  return CLIENT_CREDENTIALS;
};

/**
 * The flow's cookie is sent by the browser only to the callback (e.g. `/dev/esnacc_oauth_callback`).
 */
const getCookiePath = (): string => new URL(getRedirectURI(API_DOMAIN, STAGE)).pathname;

/**
 * The port of a local development front-end (e.g. `8100`), as for the CAS login; only on the dev stage.
 */
const parseLocalhostPort = (value: unknown): number | null => {
  if (STAGE !== 'dev' || !/^\d{1,5}$/.test(String(value ?? ''))) return null;
  const port = Number(value);
  return port >= 1 && port <= 65535 ? port : null;
};

/**
 * The front-end's sign-in page, where the flow ends (with a token or an error code).
 */
const getAuthPageURL = (localhostPort: number | null | undefined, params: Record<string, string>): string => {
  const appURL = localhostPort
    ? `http://localhost:${localhostPort}`
    : `https://${requireConfig(APP_DOMAIN, 'app domain')}`;
  const query = new URLSearchParams(params).toString();
  return `${appURL}/auth?${query}`;
};
