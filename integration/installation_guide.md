# Incode Face Authentication — Password Reset

This Action secures the Auth0 password reset flow by requiring biometric Face Authentication via [Incode](https://incode.com) before allowing a user to change their password. When a user initiates a password reset, they are redirected to Incode to complete a quick face scan. The face is matched 1:1 against the legal identity enrolled during their initial login, ensuring the person resetting the password is the same verified individual who created the account.

> ⚠️ **Prerequisite**: This Action requires the [Incode Identity Verification post-login Action](https://marketplace.auth0.com) to be installed and configured first. The post-login action stores the user's `incode_identity_id` in `app_metadata` during their first login. Without this, the password reset will be blocked.

---

## Prerequisites

Before installing this Action, ensure you have:

- The **Incode Identity Verification post-login Action** installed and working on your tenant
- Users who have completed at least one login with the post-login IDV action (so their `incode_identity_id` is stored in `app_metadata`)
- An **Incode Workforce** account with an OIDC client configured
- Your Incode **Client ID** and **Client Secret** from the Incode Workforce Dashboard

---

## Step 1: Configure your Incode OIDC client

In your **Incode Workforce Dashboard**, navigate to your OIDC client settings and confirm the following is registered as an allowed redirect URI (it should already be registered from the post-login action setup):

```
https://YOUR_AUTH0_DOMAIN/continue
```

---

## Step 2: Add this Action to your Password Reset flow

After installing this integration, navigate to **Actions → Triggers → password-reset-post-challenge** in the Auth0 Dashboard. Drag the **Incode Face Authentication — Password Reset** Action into the pipeline, then click **Apply**.

---

## Step 3: Configure the Action

### Secrets (encrypted)

| Name | Description |
| ---- | ----------- |
| `INCODE_CLIENT_ID` | Your Incode Workforce OIDC client ID |
| `INCODE_CLIENT_SECRET` | Your Incode Workforce OIDC client secret |

### Configuration

| Name | Description | Default |
| ---- | ----------- | ------- |
| `INCODE_AUTH_SERVER` | Incode OIDC auth server URL. Use `https://auth.demo.incode.com` for demo or `https://auth.incode.com` for production. | `https://auth.demo.incode.com` |
| `AUTH0_DOMAIN` | Your Auth0 tenant domain without `https://`, e.g. `your-tenant.us.auth0.com` | — |
| `SCOPES` | Space-separated OIDC scopes. | `openid` |

---

## How it works

**User initiates a password reset**
When a user clicks "Forgot Password" and follows the reset link, this Action intercepts the flow before the password change is allowed.

**Identity check**
The Action reads the user's `incode_identity_id` from their `app_metadata`. If no identity exists (the user has never completed post-login IDV), the password reset is blocked with a message to log in first.

**Face Authentication**
The user is redirected to Incode for a quick face scan. Because the `incode_identity_id` is passed as a `login_hint`, Incode performs a **1:1 biometric match** against that specific legal identity — not a general population search.

**Result**
- ✅ Face matches enrolled identity → password reset proceeds
- ❌ Face doesn't match → password reset is blocked
- ❌ Identity mismatch detected → password reset is blocked and flagged

---

## Security design

This integration uses a **1:1 biometric verification** model:

1. The user's legal identity is enrolled during their first login via the Incode IDV post-login action
2. The `incode_identity_id` is stored securely in Auth0 `app_metadata`
3. During password reset, that same identity ID is passed to Incode as `login_hint`
4. Incode verifies the live face scan matches that specific enrolled identity
5. The returned `identity_id` is compared against the enrolled one to prevent identity substitution attacks

This means an attacker who knows a user's email address cannot reset their password — they would need to physically match the enrolled user's biometric identity.

---

## Troubleshooting

<details>
<summary>Error: `identity_not_established`</summary>

The user has no `incode_identity_id` in their `app_metadata`. They must log in first with the Incode Identity Verification post-login action installed and complete the full IDV flow before they can use biometric password reset.
</details>

<details>
<summary>Error: `face_auth_failed`</summary>

The Face Authentication did not pass. This could mean the user's face did not match the enrolled identity, or the Incode session did not complete successfully. The user should contact support.
</details>

<details>
<summary>Error: `identity_mismatch`</summary>

The identity returned by Incode does not match the `incode_identity_id` stored in the user's `app_metadata`. This is a security flag indicating a potential identity substitution attempt. The user should contact support.
</details>

---

## Additional resources

- [Incode Developer Documentation](https://developer.incode.com)
- [Incode Workforce Developer Documentation](https://workforce.developer.incode.com)
- [Auth0 Post-Challenge Trigger Reference](https://auth0.com/docs/customize/actions/explore-triggers/password-reset-triggers/post-challenge-trigger)