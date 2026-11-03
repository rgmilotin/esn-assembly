/**
 * Calls to the token and userinfo endpoints of ESN Accounts (port of `src/esnaccount.ts` of ESN-Hungary/esnscope).
 */

import { URLSearchParams } from 'url';
import { default as Axios } from 'axios';

import { ENDPOINT_TOKEN, ENDPOINT_USERINFO } from './config';
import { TokenResponse, UserInfo } from './types';

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
}
export interface HttpResponse {
  status: number;
  body: string;
}

/**
 * The HTTP client used in the Lambda functions: the response's body is returned as raw text and never thrown.
 */
export const axiosHttpClient: HttpClient = {
  request: async ({ method, url, headers, body }): Promise<HttpResponse> => {
    const res = await Axios.request({
      method,
      url,
      headers,
      data: body,
      responseType: 'text',
      transformResponse: (raw: any): any => raw,
      validateStatus: (): boolean => true
    });
    return { status: res.status, body: typeof res.data === 'string' ? res.data : JSON.stringify(res.data) };
  }
};

export async function exchangeCodeForToken(
  code: string,
  clientId: string,
  clientSecret: string,
  codeVerifier: string,
  redirectUri: string,
  http: HttpClient = axiosHttpClient
): Promise<TokenResponse> {
  const body = new URLSearchParams();

  body.set('grant_type', 'authorization_code');
  body.set('code', code);
  body.set('redirect_uri', redirectUri);
  body.set('client_id', clientId);
  body.set('client_secret', clientSecret);
  body.set('code_verifier', codeVerifier);

  const response = await http.request({
    method: 'POST',
    url: ENDPOINT_TOKEN,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: body.toString()
  });

  if (!isOk(response)) throw new Error(`Token endpoint returned HTTP ${response.status}: ${truncate(response.body)}`);

  return parseJSONObject(response.body, 'Token endpoint returned invalid JSON.') as TokenResponse;
}

export async function getUserInfo(accessToken: string, http: HttpClient = axiosHttpClient): Promise<UserInfo> {
  const response = await http.request({
    method: 'GET',
    url: ENDPOINT_USERINFO,
    headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' }
  });

  if (!isOk(response))
    throw new Error(`Userinfo endpoint returned HTTP ${response.status}: ${truncate(response.body)}`);

  return parseJSONObject(response.body, 'Userinfo endpoint returned invalid JSON.') as UserInfo;
}

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
 * Error bodies of ESN Accounts are only logged (never shown to users): keep them short.
 */
const truncate = (text: string, maxLength = 300): string =>
  text && text.length > maxLength ? text.slice(0, maxLength).concat('…') : text;
