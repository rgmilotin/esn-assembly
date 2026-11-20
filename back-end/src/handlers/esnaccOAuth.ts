///
/// IMPORTS
///

import { sign } from 'jsonwebtoken';
import { DynamoDB, HandledError, ResourceController, SystemsManager } from 'idea-aws';

import {
  AUTHORIZE_PATH,
  CALLBACK_PATH,
  getClientCredentialsParameterName,
  getESNAccountsEndpoints,
  getRedirectURI,
  requireConfig
} from '../esnacc/config';
import {
  OAuthFlowError,
  buildAuthorizationURL,
  completeAuthorization,
  createCodeChallenge,
  createCodeVerifier,
  expireOAuthCookie,
  getRequestCookies,
  parseOAuthCookie,
  randomValue,
  serializeOAuthCookie
} from '../esnacc/oauth';
import { MissingUsernameError, mapUserInfoToUser } from '../esnacc/userMapping';
import { ESNDirectory, createDirectoryLoader, resolveSectionAndCountry } from '../esnacc/directory';
import { OAuthRequestCookie, UserInfo } from '../esnacc/types';

import { User } from '../models/user.model';
import { Configurations } from '../models/configurations.model';
import { ESNAccountsOAuthErrors } from '../models/esnaccOAuth.model';

///
/// CONSTANTS, ENVIRONMENT VARIABLES, HANDLER
///

const PROJECT = process.env.PROJECT;
const STAGE = process.env.STAGE;
const APP_DOMAIN = process.env.APP_DOMAIN;
const API_DOMAIN = process.env.API_DOMAIN;
const ESN_ACCOUNTS_URL = process.env.ESN_ACCOUNTS_URL;

/**
 * The lifetime of the platform's JWT for the users who sign in through OAuth.
 */
const JWT_EXPIRE_TIME = '1 day';

const DDB_TABLES = { configurations: process.env.DDB_TABLE_configurations };
const ddb = new DynamoDB();

const SECRETS_PATH = `/${PROJECT}/auth`;
const systemsManager = new SystemsManager();

let JWT_SECRET: string;
let CLIENT_CREDENTIALS: { clientId: string; clientSecret: string };
let DIRECTORY_LOADER: { load: () => Promise<ESNDirectory | null> };

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
    else if (this.resourcePath.endsWith(CALLBACK_PATH)) await this.handleCallback();
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

  /**
   * Complete the flow: validate the callback, get the profile from ESN Accounts and sign in the user (as the CAS login
   * does: same user's shape, same permissions' logic and same JWT, signed with the platform's secret).
   * Then, redirect to the front-end with the token or with an error code; the flow's cookie is always deleted.
   */
  private async handleCallback(): Promise<void> {
    const expiredCookie = expireOAuthCookie(getCookiePath());
    let oauthCookie: OAuthRequestCookie | null = null;

    try {
      const endpoints = getESNAccountsEndpoints(ESN_ACCOUNTS_URL);
      // the directory of sections and countries is loaded in parallel with the flow (it never fails nor blocks)
      const directoryPromise = this.getDirectoryLoader(endpoints).load();
      const secret = await getJwtSecretFromSystemsManager();
      oauthCookie = parseOAuthCookie(getRequestCookies(this.event), secret);
      const { clientId, clientSecret } = await getClientCredentials();

      const userInfo = await completeAuthorization({
        query: this.queryParams,
        oauthCookie,
        tokenEndpoint: endpoints.token,
        userinfoEndpoint: endpoints.userinfo,
        clientId,
        clientSecret,
        redirectURI: getRedirectURI(API_DOMAIN, STAGE)
      });
      // logged before mapping (DEBUG: only on dev), so that it's there also if the mapping fails; never tokens
      this.logger.debug('ESN Accounts OAuth userinfo received', { claims: describeClaims(userInfo) });

      const userData = resolveSectionAndCountry(mapUserInfoToUser(userInfo), await directoryPromise);
      const { userId, roles, sectionCode, section, country } = userData;
      this.logger.debug('ESN Accounts OAuth userinfo mapped', { userId, roles, sectionCode, section, country });

      const { administratorsIds, opportunitiesManagersIds, dashboardManagersIds } =
        await this.loadOrInitConfigurations(userId);

      const user = new User({
        ...userData,
        isAdministrator: administratorsIds.includes(userId),
        canManageOpportunities: administratorsIds.includes(userId) || opportunitiesManagersIds.includes(userId),
        canManageDashboard: administratorsIds.includes(userId) || dashboardManagersIds.includes(userId)
      });
      this.logger.info('ESN Accounts OAuth login', { userId: user.userId });

      const userJWTData = JSON.parse(JSON.stringify(user));
      const token = sign(userJWTData, secret, { expiresIn: JWT_EXPIRE_TIME });

      this.redirect(getAuthPageURL(oauthCookie.localhostPort, { token }), [expiredCookie]);
    } catch (err) {
      let errorCode = ESNAccountsOAuthErrors.GENERIC;
      if (err instanceof OAuthFlowError) errorCode = err.code;
      else if (err instanceof MissingUsernameError) errorCode = ESNAccountsOAuthErrors.NO_USERNAME;
      this.logger.error('ESN ACCOUNTS OAUTH: CALLBACK', { errorCode, message: (err as Error)?.message });

      this.redirect(getAuthPageURL(oauthCookie?.localhostPort, { error: errorCode }), [expiredCookie]);
    }
  }

  /**
   * The loader of ESN Accounts' directory of sections and countries, cached for the Lambda's lifetime.
   */
  private getDirectoryLoader(endpoints: { sections: string; countries: string }): {
    load: () => Promise<ESNDirectory | null>;
  } {
    if (!DIRECTORY_LOADER)
      DIRECTORY_LOADER = createDirectoryLoader({
        sectionsEndpoint: endpoints.sections,
        countriesEndpoint: endpoints.countries,
        onError: err => this.logger.warn('ESN Accounts directory unavailable', err)
      });
    return DIRECTORY_LOADER;
  }

  /**
   * Same as the CAS login (`login.ts`): the first user to sign in becomes administrator.
   */
  private async loadOrInitConfigurations(firstAdminId: string): Promise<Configurations> {
    try {
      return new Configurations(
        await ddb.get({ TableName: DDB_TABLES.configurations, Key: { PK: Configurations.PK } })
      );
    } catch (err) {
      if (String(err) === 'Error: Not found') {
        const configurations = new Configurations({ PK: Configurations.PK, administratorsIds: [firstAdminId] });
        await ddb.put({
          TableName: DDB_TABLES.configurations,
          Item: configurations,
          ConditionExpression: 'attribute_not_exists(PK)'
        });
        return configurations;
      } else throw new HandledError('Error loading configuration');
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

/**
 * The names of the userinfo's claims, with the type of their values (not the values).
 */
const describeClaims = (userInfo: UserInfo): Record<string, string> =>
  Object.fromEntries(
    Object.entries(userInfo).map(([claim, value]) => [
      claim,
      Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value
    ])
  );
