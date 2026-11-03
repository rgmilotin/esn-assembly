import { parameters, stages } from '../../../back-end/deploy/environments';

/**
 * The stage to use for API (and websocket) requests.
 */
const STAGE = 'dev';

/**
 * Variables to configure an ITER IDEA's cloud app, together with its inner modules.
 */
export const environment = {
  idea: {
    app: { version: '1.10.3', mediaUrl: 'https://'.concat(parameters.mediaDomain), maxFileUploadSizeMB: 50 },
    api: { url: parameters.apiDomain, stage: STAGE },
    socket: { url: parameters.webSocketApiDomain, stage: STAGE },
    ionicExtraModules: ['common']
  },
  /**
   * Whether the API stage supports the sign-in with ESN Accounts through OAuth 2.0 (and shows the Google sign-in).
   */
  esnAccountsOAuth: !!stages[STAGE]?.esnAccountsOAuth
};
