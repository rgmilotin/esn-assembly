import { Component, Input, OnInit } from '@angular/core';
import { ToastController } from '@ionic/angular';
import { IDEAStorageService, IDEATranslationsService } from '@idea-ionic/common';

import { AppService } from '../app.service';

import { ESNACC_OAUTH_AUTHORIZE_PATH, ESNAccountsOAuthErrors } from '@models/esnaccOAuth.model';

import { environment as env } from '@env';

@Component({
  selector: 'auth-page',
  templateUrl: 'auth.page.html',
  styleUrls: ['auth.page.scss']
})
export class AuthPage implements OnInit {
  @Input() token: string;
  /**
   * The error of a failed sign-in with ESN Accounts through OAuth 2.0 (see `ESNAccountsOAuthErrors`).
   */
  @Input() error: string;

  version = env.idea.app.version;
  esnAccountsOAuth = env.esnAccountsOAuth;

  constructor(
    private toastCtrl: ToastController,
    private storage: IDEAStorageService,
    private t: IDEATranslationsService,
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
      const errorKey =
        Object.keys(ESNAccountsOAuthErrors).find(
          key => ESNAccountsOAuthErrors[key as keyof typeof ESNAccountsOAuthErrors] === this.error
        ) ?? 'GENERIC';
      await this.showMessageOnTop(`AUTH.ESNACC_OAUTH_ERRORS.${errorKey}`, 'danger');
    }
  }

  startLoginFlowWithESNAccounts(): void {
    const apiLoginURL = `https://${env.idea.api.url}/${env.idea.api.stage}/login`;
    const localhost = location.hostname.startsWith('localhost') ? '?localhost=8100' : '';
    window.location.assign(`https://accounts.esn.org/cas/login?service=${apiLoginURL}${localhost}`);
  }

  startLoginFlowWithESNAccountsOAuth(): void {
    const apiAuthorizeURL = `https://${env.idea.api.url}/${env.idea.api.stage}${ESNACC_OAUTH_AUTHORIZE_PATH}`;
    const localhost = location.hostname.startsWith('localhost') ? '?localhost=8100' : '';
    window.location.assign(`${apiAuthorizeURL}${localhost}`);
  }

  async startLoginFlowWithGoogle(): Promise<void> {
    await this.showMessageOnTop('AUTH.GOOGLE_COMING_SOON', 'dark');
  }

  private async showMessageOnTop(message: string, color: string): Promise<void> {
    const toast = await this.toastCtrl.create({
      message: this.t._(message),
      color,
      position: 'top',
      duration: 5000,
      buttons: [{ text: 'X', role: 'cancel' }]
    });
    await toast.present();
  }
}

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
