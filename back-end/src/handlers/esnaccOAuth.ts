///
/// IMPORTS
///

import { sign } from 'jsonwebtoken';
import { DynamoDB, HandledError, ResourceController, SystemsManager } from 'idea-aws';

import { getClientCredentialsParameterName, getCookiePath, getRedirectUri, requireConfig } from '../esnacc/config';
import {
  OAuthFlowError,
  buildAuthorizationUrl,
  completeAuthorization,
  createCodeChallenge,
  expireOAuthCookie,
  getRequestCookies,
  parseOAuthCookie,
  randomValue,
  serializeOAuthCookie
} from '../esnacc/oauth';
import { extractRoles } from '../esnacc/roles';
import { MissingLegacyIdError, mapUserInfoToUser } from '../esnacc/userMapping';
import { OAuthRequestCookie } from '../esnacc/types';

import { User } from '../models/user.model';
import { Configurations } from '../models/configurations.model';
import { ESNACC_OAUTH_CALLBACK_PATH, ESNAccountsOAuthErrors } from '../models/esnaccOAuth.model';

///
/// CONSTANTS, ENVIRONMENT VARIABLES, HANDLER
///

const JWT_EXPIRE_TIME = '1 day';

const PROJECT = process.env.PROJECT;
const STAGE = process.env.STAGE;
const API_DOMAIN = process.env.API_DOMAIN;
const APP_DOMAIN = process.env.APP_DOMAIN;
const APP_URL = 'https://'.concat(APP_DOMAIN);

const DDB_TABLES = { configurations: process.env.DDB_TABLE_configurations };
const ddb = new DynamoDB();

const SECRETS_PATH = `/${PROJECT}/auth`;
const systemsManager = new SystemsManager();

let JWT_SECRET: string;
let CLIENT_CREDENTIALS: { clientId: string; clientSecret: string };

export const handler = (ev: any, _: any, cb: any): Promise<void> => new ESNAccountsOAuth(ev, cb).handleRequest();

///
/// RESOURCE CONTROLLER
///

/**
 * Sign-in with ESN Accounts through OAuth 2.0 (authorization code + PKCE), alternative to the CAS login (`login.ts`).
 * It produces the same user and token as the CAS login, so the rest of the platform works the same way.
 */
class ESNAccountsOAuth extends ResourceController {
  constructor(event: any, callback: any) {
    super(event, callback);
    this.callback = callback;
  }

  protected async getResources(): Promise<any> {
    if (this.resourcePath.endsWith(ESNACC_OAUTH_CALLBACK_PATH)) await this.handleCallback();
    else await this.startAuthorization();
  }

  /**
   * Redirect the user to ESN Accounts, keeping the flow's `state` and PKCE verifier in a short-lived cookie.
   */
  private async startAuthorization(): Promise<void> {
    const localhostPort = parseLocalhostPort(this.queryParams.localhost);
    try {
      const { clientId } = await getClientCredentials();
      const state = randomValue();
      const codeVerifier = randomValue(64);

      const authorizationURL = buildAuthorizationUrl({
        clientId,
        redirectUri: getRedirectUri(requireConfig(API_DOMAIN, 'API_DOMAIN'), STAGE),
        state,
        codeChallenge: createCodeChallenge(codeVerifier)
      });
      const oauthCookie: OAuthRequestCookie = { state, codeVerifier };
      if (localhostPort) oauthCookie.localhostPort = localhostPort;
      const cookie = serializeOAuthCookie(oauthCookie, await getJwtSecretFromSystemsManager(), getCookiePath(STAGE));

      this.redirect(authorizationURL, [cookie]);
    } catch (err) {
      this.logger.error('ESN ACCOUNTS OAUTH: START', err);
      this.redirect(getAuthPageURL(localhostPort, { error: ESNAccountsOAuthErrors.GENERIC }), []);
    }
  }

  /**
   * Complete the flow: validate the callback, get the profile from ESN Accounts and sign in the user.
   */
  private async handleCallback(): Promise<void> {
    const expiredCookie = expireOAuthCookie(getCookiePath(STAGE));
    let oauthCookie: OAuthRequestCookie | null = null;

    try {
      const secret = await getJwtSecretFromSystemsManager();
      oauthCookie = parseOAuthCookie(getRequestCookies(this.event), secret);
      const { clientId, clientSecret } = await getClientCredentials();

      const userInfo = await completeAuthorization({
        query: this.queryParams,
        oauthCookie,
        clientId,
        clientSecret,
        redirectUri: getRedirectUri(requireConfig(API_DOMAIN, 'API_DOMAIN'), STAGE)
      });
      const roles = extractRoles(userInfo);
      const userData = mapUserInfoToUser(userInfo, roles);
      // to verify the (best-effort) mapping on dev: claims' names and mapped values only, never tokens
      const { userId, sectionCode, section, country } = userData;
      this.logger.debug('ESN Accounts OAuth userinfo mapped', {
        claims: Object.keys(userInfo),
        roles,
        mapped: { userId, roles: userData.roles, sectionCode, section, country }
      });

      const { administratorsIds, opportunitiesManagersIds, dashboardManagersIds } = await this.loadOrInitConfigurations(
        userData.userId
      );

      const user = new User({
        ...userData,
        isAdministrator: administratorsIds.includes(userData.userId),
        canManageOpportunities:
          administratorsIds.includes(userData.userId) || opportunitiesManagersIds.includes(userData.userId),
        canManageDashboard:
          administratorsIds.includes(userData.userId) || dashboardManagersIds.includes(userData.userId)
      });
      this.logger.info('ESN Accounts OAuth login', { userId: user.userId });

      const userJWTData = JSON.parse(JSON.stringify(user));
      const token = sign(userJWTData, secret, { expiresIn: JWT_EXPIRE_TIME });

      // redirect to the front-end with the fresh new token, like the CAS login
      this.redirect(getAuthPageURL(oauthCookie.localhostPort, { token }), [expiredCookie]);
    } catch (err) {
      let errorCode = ESNAccountsOAuthErrors.GENERIC;
      if (err instanceof OAuthFlowError) errorCode = err.code;
      if (err instanceof MissingLegacyIdError) errorCode = ESNAccountsOAuthErrors.NO_LEGACY_ID;
      this.logger.error('ESN ACCOUNTS OAUTH: CALLBACK', { errorCode, message: (err as Error)?.message });

      this.redirect(getAuthPageURL(oauthCookie?.localhostPort, { error: errorCode }), [expiredCookie]);
    }
  }

  private redirect(location: string, cookies: string[]): void {
    this.callback(null, {
      statusCode: 302,
      headers: { Location: location, 'Cache-Control': 'no-store' },
      cookies
    });
  }

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
}

const getJwtSecretFromSystemsManager = async (): Promise<string> => {
  if (!JWT_SECRET) JWT_SECRET = await systemsManager.getSecretByName(SECRETS_PATH);
  return JWT_SECRET;
};

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
 * The port of a local development front-end (e.g. `8100`), as for the CAS login; only valid ports are accepted.
 */
const parseLocalhostPort = (value: unknown): number | null => {
  if (!/^\d{1,5}$/.test(String(value ?? ''))) return null;
  const port = Number(value);
  return port >= 1 && port <= 65535 ? port : null;
};

const getAuthPageURL = (localhostPort: number | null | undefined, params: Record<string, string>): string => {
  const appURL = localhostPort ? `http://localhost:${localhostPort}` : APP_URL;
  const query = Object.entries(params)
    .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
    .join('&');
  return `${appURL}/auth?${query}`;
};
