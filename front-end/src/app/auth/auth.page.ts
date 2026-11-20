import { Component, Input, OnInit } from '@angular/core';
import { IDEAMessageService, IDEAStorageService } from '@idea-ionic/common';

import { AppService } from '../app.service';

import { ESNAccountsOAuthErrors } from '@models/esnaccOAuth.model';

import { environment as env } from '@env';

@Component({
  selector: 'auth-page',
  templateUrl: 'auth.page.html',
  styleUrls: ['auth.page.scss']
})
export class AuthPage implements OnInit {
  @Input() token: string;
  /**
   * The error code of a failed sign-in with ESN Accounts through OAuth 2.0 (see `ESNAccountsOAuthErrors`).
   */
  @Input() error: string;

  version = env.idea.app.version;

  constructor(
    private storage: IDEAStorageService,
    private message: IDEAMessageService,
    public app: AppService
  ) {}
  async ngOnInit(): Promise<void> {
    // complete the flow from ESN Accounts
    if (this.token) {
      const user = parseJWT(this.token);
      const tokenExpiresAt = user.exp * 1000;
      if (tokenExpiresAt > Date.now()) {
        await this.storage.set('token', this.token);
        await this.storage.set('tokenExpiresAt', tokenExpiresAt);
        await this.storage.set('user', user);
      }
      window.location.assign('');
    } else if (this.error) {
      // remove the error from the URL, so that the message isn't shown again on reload
      window.history.replaceState(null, '', window.location.pathname);
      await this.message.error(getOAuthErrorMessageKey(this.error));
    }
  }

  startLoginFlowWithESNAccounts(): void {
    const apiLoginURL = `https://${env.idea.api.url}/${env.idea.api.stage}/login`;
    const localhost = location.hostname.startsWith('localhost') ? '?localhost=8100' : '';
    window.location.assign(`https://accounts.esn.org/cas/login?service=${apiLoginURL}${localhost}`);
  }

  /**
   * Start the sign-in with ESN Accounts through OAuth 2.0: the API redirects to ESN Accounts and, at the end of the
   * flow, back to this page with a token (or an error code). The API's URL comes from the stage's configuration.
   */
  startLoginFlowWithESNAccountsOAuth(): void {
    const apiAuthorizeURL = `https://${env.idea.api.url}/${env.idea.api.stage}/esnacc_oauth_authorize`;
    const localhost = location.hostname.startsWith('localhost') ? `?localhost=${location.port || 8100}` : '';
    window.location.assign(`${apiAuthorizeURL}${localhost}`);
  }

  /**
   * The sign-in with Google isn't available yet: there's no back-end for it, only a message.
   */
  async startLoginFlowWithGoogle(): Promise<void> {
    await this.message.info('AUTH.GOOGLE_COMING_SOON');
  }
}

/**
 * The (translation key of the) message for an error code of the OAuth sign-in; unknown codes get the generic one.
 */
const getOAuthErrorMessageKey = (errorCode: string): string => {
  const errorKey = Object.keys(ESNAccountsOAuthErrors).find(
    key => ESNAccountsOAuthErrors[key as keyof typeof ESNAccountsOAuthErrors] === errorCode
  );
  return `AUTH.OAUTH_ERRORS.${errorKey ?? 'GENERIC'}`;
};

/**
 * Parse a JWT token without using external libraries.
 */
const parseJWT = (token: string): any => {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = decodeURIComponent(
    window
      .atob(base64)
      .split('')
      .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
      .join('')
  );
  return JSON.parse(jsonPayload);
};
