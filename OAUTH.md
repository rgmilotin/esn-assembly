# Sign-in with ESN Accounts through OAuth 2.0

The app can sign users in with ESN Accounts in two ways:

1. **Sign in with ESN Accounts**: the original CAS login (`back-end/src/handlers/login.ts`), unchanged.
2. **Sign in with ESN Accounts (OAuth)**: OAuth 2.0 authorization code with PKCE, implemented following
   [`ESNacc_OAUTH_INTEGRATION_SPEC.md`](https://github.com/ESN-Hungary/esnscope/blob/main/ESNacc_OAUTH_INTEGRATION_SPEC.md)
   (ESN-Hungary/esnscope).

The sign-in page also shows a **Sign in with Google** button, which is only a placeholder for now: pressing it shows a
"coming soon" message.

**The OAuth sign-in (and the Google button) is enabled only in the `dev` stage.** Production is unaffected: the OAuth
Lambda function and its API routes are not deployed there, and the front-end shows only the CAS button when it targets
the `prod` API.

## How it works

```text
Browser                         GA app API (dev)                            ESN Accounts
   | "Sign in with ESN Accounts (OAuth)"
   |--- GET /dev/esnacc_oauth_authorize ---->|
   |<-- 302 + signed cookie (state, PKCE) ---|
   |--- GET /oauth/authorize (user signs in) ---------------------------------->|
   |<-- 302 to /dev/esnacc_oauth_callback?code&state ---------------------------|
   |--- GET /dev/esnacc_oauth_callback ------>|--- POST /oauth/token ------------>|
   |                                          |<-- access token (used once) -----|
   |                                          |--- GET /oauth/v2/userinfo ------->|
   |                                          |<-- profile ----------------------|
   |                     map the profile to the same user as the CAS login,
   |                     sign the platform's token (as the CAS login does)
   |<-- 302 to /auth?token=… (or /auth?error=…)
```

After this, everything works exactly as with the CAS login: the token has the same content and is signed with the
same secret.

**The user ID is the legacy (CAS) username**, read from the `sub_legacy` claim. This way, a person signing in with
either button is the same user in the app (same admin rights, badges, questions, etc.). If the profile has no
`sub_legacy`, the sign-in is refused and the user is asked to use the CAS button.

### Files

| File                                       | Responsibility                                                             |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| `back-end/src/handlers/esnaccOAuth.ts`     | Lambda function: `/esnacc_oauth_authorize` and `/esnacc_oauth_callback`    |
| `back-end/src/esnacc/config.ts`            | Endpoints, scope, redirect URI, cookie settings, SSM parameter name        |
| `back-end/src/esnacc/types.ts`             | ESN Accounts entities (from the spec)                                      |
| `back-end/src/esnacc/esnaccount.ts`        | Token exchange and userinfo calls                                          |
| `back-end/src/esnacc/oauth.ts`             | PKCE, signed state cookie, callback validation                             |
| `back-end/src/esnacc/roles.ts`             | Role extraction (`groups` and `detailed_groups`)                           |
| `back-end/src/esnacc/userMapping.ts`       | Mapping of the profile to the platform's user (best effort, see below)     |
| `back-end/src/models/esnaccOAuth.model.ts` | API paths and error codes, shared with the front-end                       |
| `back-end/test/esnacc.test.ts`             | Tests (they include the spec's acceptance tests): `cd back-end; npm test`  |
| `back-end/deploy/environments.ts`          | `esnAccountsOAuth: true` enables the feature in a stage (only `dev` today) |
| `front-end/src/app/auth/*`                 | The three sign-in buttons and the error messages                           |

## Set up (dev stage)

1. **Register the OAuth client with ESN Accounts** (ask the ESN Accounts administrators). Use this redirect URI,
   exactly as written (no trailing slash; it must match byte for byte):

   ```text
   https://api.assembly.esn.hu/dev/esnacc_oauth_callback
   ```

   Scope: `oauth2_access_to_profile_information`. When production is enabled later, the same client can also get
   `https://api.assembly.esn.hu/prod/esnacc_oauth_callback`.

1. **Store the client's credentials in AWS Systems Manager** (Parameter Store), as an encrypted parameter, next to the
   app's existing `/esn-assembly-hu/auth` secret. Never commit them or share them in chats.

   ```sh
   aws ssm put-parameter --profile esn-assembly-hu --type "SecureString" \
     --name "/esn-assembly-hu/esnacc-oauth" \
     --value '{"clientId":"<CLIENT_ID>","clientSecret":"<CLIENT_SECRET>"}'
   ```

   To change them later, run the same command with `--overwrite`. Use the same region where the back-end is deployed.

1. **Deploy the dev back-end**: from Visual Studio Code, "Terminal > Run build task" > "Deploy a back-end environment" >
   `dev`; or, from the `back-end` folder: `bash deploy.sh dev`.
   This creates the `esn-assembly-hu_dev_esnaccOAuth` Lambda function and the two API routes, in dev only.

1. **Release the dev front-end**: make sure `STAGE` is `'dev'` in `front-end/src/environments/environment.idea.ts`,
   then "Terminal > Run build task" > "Release a front-end environment" > `dev`; or, from the `front-end` folder:
   `bash release.sh dev`.

1. **Try it** on https://dev.assembly.esn.hu: the sign-in page shows three buttons and the version `v1.10.3`.
   Local development works too (`npm start` in `front-end`, then http://localhost:8100), like the CAS login.

Note: as for the CAS login, on an empty database the first user to sign in becomes administrator.

## Verify the profile mapping (important)

The mapping of roles, section and country from the OAuth profile is **best effort**: the format hadn't been checked with
real profiles when this was written. Every guess is marked `ASSUMPTION` in `back-end/src/esnacc/userMapping.ts`.

To check it on dev:

1. Sign in once with the CAS button and once with the OAuth button, with the same account.
1. Compare the two users. In the browser's developer tools (Network tab, with "Preserve log" on), find the request to
   `/auth?token=…` after each sign-in and copy the token's middle part (between the two dots); decode it in the browser's
   console with `JSON.parse(atob('<middle part>'.replace(/-/g, '+').replace(/_/g, '/')))`. Never paste tokens in online
   tools. `userId`, `email`, names, `roles`, `sectionCode`, `section` and `country` should be the same.
1. Check the CloudWatch logs of the `esn-assembly-hu_dev_esnaccOAuth` function: the "ESN Accounts OAuth userinfo
   mapped" entry (dev logs at DEBUG level) lists the claims received, the roles found and the mapped values; it never
   contains tokens or personal data other than the user ID and the role/section/country values.
1. Fix the rules in `userMapping.ts` and the related tests if something differs, then redeploy dev.

What happens with each field today:

| User field              | Taken from                                                                                                                                                 |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `userId`                | `sub_legacy`, lower-cased (sign-in refused when missing)                                                                                                   |
| `email`                 | `email`, else `esn_email`                                                                                                                                  |
| `firstName`, `lastName` | `given_name`, `family_name`, else split from `name`                                                                                                        |
| `avatarURL`             | `picture`                                                                                                                                                  |
| `roles`                 | `groups` and `detailed_groups`, translated to the CAS format (e.g. `SECTION:regular-board-member` → `Local.regularBoardMember`); unknown roles are skipped |
| `section`, `country`    | `detailed_groups` of type `section` / `country`, else top-level `section` / `country` claims                                                               |
| `sectionCode`           | `sc`, `section_code` or `sectionCode` claims, if any                                                                                                       |

When a role or the section can't be found, the sign-in still works, but topics restricted to some roles may not be
available to that user, and their section won't be shown.

## Errors

On failure, the user is sent back to the sign-in page (`/auth?error=<code>`), where a message is shown at the top.

| Code              | Meaning                                                             |
| ----------------- | ------------------------------------------------------------------- |
| `access_denied`   | The user cancelled or denied the access on ESN Accounts             |
| `invalid_request` | ESN Accounts returned an error, or no authorization code            |
| `invalid_state`   | The flow's cookie is missing, expired (10 minutes) or doesn't match |
| `esnacc_error`    | The token or userinfo endpoint of ESN Accounts failed               |
| `no_legacy_id`    | The profile has no `sub_legacy`: the user should use the CAS button |
| `generic`         | Anything else (e.g. the credentials are missing in Systems Manager) |

Details are in the CloudWatch logs of the `esn-assembly-hu_dev_esnaccOAuth` function.

## Security notes

- PKCE (S256) and `state`, compared in constant time; the code verifier never leaves the back-end and the user's browser.
- The flow's cookie is HttpOnly, Secure, SameSite=Lax, limited to the callback path, valid 10 minutes, and signed with a
  key derived from the app's secret (so it can't be used as an API token).
- The redirect URI is fixed per stage, never built from the request's headers.
- The client secret lives only in AWS Systems Manager; ESN Accounts' access token is used once and discarded; tokens are
  never logged.
- Only the fields the CAS login already stores are kept: address, birth date, gender, etc. are ignored.

## Enable it in production (later)

1. Add the prod redirect URI to the OAuth client (see above).
1. In `back-end/deploy/environments.ts`, add `esnAccountsOAuth: true` to the `prod` stage.
1. Deploy the prod back-end, then release the prod front-end (with `STAGE = 'prod'`).
