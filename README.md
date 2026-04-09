# Incode Face Authentication — Auth0 Password Reset Action

This integration adds [Incode's](https://incode.com) biometric Face Authentication to the Auth0 password reset flow. When a user initiates a password reset, they are redirected to Incode to complete a face scan. The face is matched 1:1 against the legal identity enrolled during their initial login, ensuring the person resetting the password is the same verified individual who created the account.

> ⚠️ **Prerequisite**: This Action requires the [Incode Identity Verification post-login Action](https://marketplace.auth0.com) to be installed first.

## Features

- **1:1 biometric verification** — face is matched against the specific enrolled legal identity, not a general population search
- **Blocks unverified users** — if no identity has been enrolled, the password reset is blocked
- **Identity substitution protection** — verifies the returned identity matches the enrolled one
- **Seamless UX** — users complete a quick face scan and are returned to the reset flow automatically

## How It Works

```
User clicks "Forgot Password"
           │
           ▼
Post-challenge Action fires
           │
           ├── Has incode_identity_id in app_metadata?
           │         └── No → deny with identity_not_established
           │
           └── Yes → redirect to Incode Face Auth
                            │
                            ▼
                    1:1 face scan against enrolled identity
                            │
                            ├── auth_overall_status = OK + identity matches → allow reset
                            ├── auth_overall_status ≠ OK → deny with face_auth_failed
                            └── identity mismatch → deny with identity_mismatch
```

## Prerequisites

- The **Incode Identity Verification post-login Action** must be installed and users must have completed at least one login with it
- An [Incode Workforce](https://workforce.incode.com) account with an OIDC client configured
- `https://YOUR_AUTH0_DOMAIN/continue` registered as an allowed redirect URI in your Incode OIDC client

## Configuration

| Parameter | Type | Description |
| --------- | ---- | ----------- |
| `INCODE_CLIENT_ID` | Secret | Your Incode Workforce OIDC client ID |
| `INCODE_CLIENT_SECRET` | Secret | Your Incode Workforce OIDC client secret |
| `INCODE_AUTH_SERVER` | Configuration | Incode OIDC auth server URL (`https://auth.demo.incode.com` or `https://auth.incode.com`) |
| `AUTH0_DOMAIN` | Configuration | Your Auth0 tenant domain (e.g. `your-tenant.us.auth0.com`) |
| `SCOPES` | Configuration | Space-separated OIDC scopes. Default: `openid` |

## OIDC Endpoints

| Environment | Authorization | Token | UserInfo |
| ----------- | ------------- | ----- | -------- |
| Demo | `https://auth.demo.incode.com/oauth2/authorize` | `https://auth.demo.incode.com/oauth2/token` | `https://auth.demo.incode.com/userinfo` |
| Production | `https://auth.incode.com/oauth2/authorize` | `https://auth.incode.com/oauth2/token` | `https://auth.incode.com/userinfo` |

## Installation

See [INSTALLATION.md](integration/INSTALLATION.md) for full setup instructions.

## Testing

Requires [Docker](https://www.docker.com/products/docker-desktop).

```bash
make test
```

## Resources

- [Incode Developer Documentation](https://developer.incode.com)
- [Incode Workforce Developer Documentation](https://workforce.developer.incode.com)
- [Auth0 Post-Challenge Trigger Reference](https://auth0.com/docs/customize/actions/explore-triggers/password-reset-triggers/post-challenge-trigger)

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.