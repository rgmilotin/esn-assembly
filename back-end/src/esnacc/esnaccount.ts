/**
 * Calls to the token and userinfo endpoints of ESN Accounts (as in `src/esnaccount.ts` of ESN-Hungary/esnscope).
 */

import { URLSearchParams } from 'url';
import { default as Axios } from 'axios';

import { TokenResponse, UserInfo } from './types';

/**
 * How long to wait for ESN Accounts before failing a request.
 */
const REQUEST_TIMEOUT_MS = 10_000;

/**
 * A minimal HTTP client, so that the requests to ESN Accounts can be replaced in tests.
 */
export interface HttpClient {
  request(options: HttpRequest): Promise<HttpResponse>;
}
export interface HttpRequest {
  method: 'GET' | 'POST';
  url: string;
  headers: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}
export interface HttpResponse {
  status: number;
  body: string;
}

/**
 * The HTTP client used in the Lambda functions: the response's body is returned as raw text and never thrown.
 */
export const axiosHttpClient: HttpClient = {
  request: async ({ method, url, headers, body, timeoutMs }): Promise<HttpResponse> => {
    const res = await Axios.request({
      method,
      url,
      headers,
      data: body,
      timeout: timeoutMs ?? REQUEST_TIMEOUT_MS,
      responseType: 'text',
      transformResponse: (raw: any): any => raw,
      validateStatus: (): boolean => true
    });
    return { status: res.status, body: typeof res.data === 'string' ? res.data : JSON.stringify(res.data) };
  }
};

/**
 * Exchange the authorization code for an access token (authorization code grant with PKCE).
 * The `redirectURI` must be the same one used in the authorization request.
 */
export const exchangeCodeForToken = async (params: {
  tokenEndpoint: string;
  code: string;
  clientId: string;
  clientSecret: string;
  codeVerifier: string;
  redirectURI: string;
  http?: HttpClient;
}): Promise<TokenResponse> => {
  const http = params.http ?? axiosHttpClient;
  const body = new URLSearchParams();

  body.set('grant_type', 'authorization_code');
  body.set('code', params.code);
  body.set('redirect_uri', params.redirectURI);
  body.set('client_id', params.clientId);
  body.set('client_secret', params.clientSecret);
  body.set('code_verifier', params.codeVerifier);

  const response = await http.request({
    method: 'POST',
    url: params.tokenEndpoint,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: body.toString()
  });

  if (!isOk(response)) throw new Error(`Token endpoint returned HTTP ${response.status}${describeError(response)}`);

  return parseJSONObject(response.body, 'Token endpoint returned invalid JSON') as TokenResponse;
};

/**
 * Get the user's profile with the access token.
 */
export const getUserInfo = async (params: {
  userinfoEndpoint: string;
  accessToken: string;
  http?: HttpClient;
}): Promise<UserInfo> => {
  const http = params.http ?? axiosHttpClient;

  const response = await http.request({
    method: 'GET',
    url: params.userinfoEndpoint,
    headers: { Authorization: `Bearer ${params.accessToken}`, Accept: 'application/json' }
  });

  if (!isOk(response)) throw new Error(`Userinfo endpoint returned HTTP ${response.status}${describeError(response)}`);

  return parseJSONObject(response.body, 'Userinfo endpoint returned invalid JSON') as UserInfo;
};

const isOk = (response: HttpResponse): boolean => response.status >= 200 && response.status < 300;

const parseJSONObject = (text: string, errorMessage: string): Record<string, unknown> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(errorMessage);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(errorMessage);
  return parsed as Record<string, unknown>;
};

/**
 * Only the standard OAuth `error` code of an error response is reported (never the raw body), so that nothing
 * sensitive can end up in the logs.
 */
const describeError = (response: HttpResponse): string => {
  try {
    const { error } = JSON.parse(response.body);
    return typeof error === 'string' && /^[\w.-]{1,64}$/.test(error) ? ` (${error})` : '';
  } catch {
    return '';
  }
};
