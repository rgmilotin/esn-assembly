# Sign-in with ESN Accounts through OAuth 2.0

The sign-in page offers:

1. **Sign in with ESN Accounts**: the original CAS login (`back-end/src/handlers/login.ts`), unchanged.
2. **Sign in with ESN Accounts (OAuth)**: OAuth 2.0 authorization code with PKCE, following
   [`ESNacc_OAUTH_INTEGRATION_SPEC.md`](https://github.com/ESN-Hungary/esnscope/blob/main/ESNacc_OAUTH_INTEGRATION_SPEC.md).
3. **Sign in with Google**: a placeholder for now (it shows a "coming soon" message).

## How it works

```text
Browser                          GA app API                                  ESN Accounts
   |--- GET /<stage>/esnacc_oauth_authorize -->|
   |<-- 302 + signed cookie (state, PKCE) -----|
   |--- GET /oauth/authorize (user signs in) ----------------------------------->|
   |<-- 302 to /<stage>/esnacc_oauth_callback?code&state ------------------------|
   |--- GET /<stage>/esnacc_oauth_callback --->|--- POST /oauth/token ----------->|
   |                                           |--- GET /oauth/v2/userinfo ------>|
   |                  map the profile to the platform's user and sign its token, as the CAS login does
   |<-- 302 to /auth?token=… (or /auth?error=…)
```

The redirect URI is built from the request, as the CAS login builds its service URL:
`https://<API domain>/<stage>/esnacc_oauth_callback`. ESN Accounts' address is in `back-end/src/esnacc/config.ts`.

## The user

| User field              | From the userinfo                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------- |
| `userId`                | `preferred_username`, lower-cased (the sign-in is refused without it)              |
| `email`                 | `esn_email` (as the CAS login), else `email`                                       |
| `firstName`, `lastName` | `given_name`, `family_name`                                                        |
| `avatarURL`             | `picture`                                                                          |
| `roles`                 | `groups`, as returned: `<scope>:<role>`, e.g. `HU-BUDA-ELTE:section-active_member` |
| `sectionCode`           | `scope` of the first `detailed_groups` of type `section`, e.g. `HU-BUDA-ELTE`      |
| `section`               | `label` of the same group, e.g. `ESN ELTE`                                         |
| `country`               | "ESN " + the country of the section code, e.g. `HU` → `ESN Hungary`                |

The platform's roles (e.g. "national board", used to restrict who can interact with a topic) recognise both the CAS
and the OAuth roles, as listed in the
[ESN Accounts - roles mapping](https://docs.google.com/spreadsheets/d/e/2PACX-1vRdzqFX1zRyOoAZxsrAWYxEuE0xs_0hX-8Jk10yAwEeC-WE81W2orTtkYjCPH-lrBsGu_lB-bbzlaKf/pubhtml)
sheet: see `ESN_ACCOUNTS_ROLES_MAP` in `back-end/src/models/user.model.ts`.

## Set up

1. **Register the OAuth client with ESN Accounts**, with a redirect URI for each stage, exactly as:
   `https://api.assembly.esn.hu/dev/esnacc_oauth_callback` and `https://api.assembly.esn.hu/prod/esnacc_oauth_callback`.
   Scope: `oauth2_access_to_profile_information`.
1. **Store the client's credentials in AWS Systems Manager**, next to the app's `/esn-assembly-hu/auth` secret:
   ```sh
   aws ssm put-parameter --profile esn-assembly-hu --type "SecureString" --name "/esn-assembly-hu/esnacc-oauth" \
     --value '{"clientId":"<CLIENT_ID>","clientSecret":"<CLIENT_SECRET>"}'
   ```
1. **Deploy** the back-end and release the front-end of the stage, as usual (`HOW-TO-DEPLOY.md`).

Tests: `cd back-end; npm test`. On dev, the Lambda function `esn-assembly-hu_dev_esnaccOAuth` logs (DEBUG) the names
of the userinfo's claims and the values mapped; never tokens.

## Errors

On failure, the user is sent back to the sign-in page (`/auth?error=<code>`), where a message is shown.

| Code              | Meaning                                                              |
| ----------------- | -------------------------------------------------------------------- |
| `access_denied`   | The user cancelled or denied the access on ESN Accounts              |
| `invalid_request` | ESN Accounts returned an error, or no authorization code             |
| `invalid_state`   | The flow's cookie is missing, expired (10 minutes) or doesn't match  |
| `esnacc_error`    | The token or userinfo endpoint of ESN Accounts failed                |
| `no_username`     | The profile has no `preferred_username`                              |
| `generic`         | Anything else (e.g. the client's credentials are missing in AWS SSM) |
