/**
 * Incode Face Authentication — Auth0 Password Reset / Post Challenge Action
 *
 * Secures the password reset flow by requiring biometric Face Authentication
 * via Incode before allowing the user to change their password.
 *
 * Security design:
 *   - Requires the user to have completed post-login IDV first via the Incode
 *     Identity Verification post-login action. The incode_identity_id stored
 *     in app_metadata during that flow is used as the login_hint to force a
 *     1:1 Face Auth against the specific legal identity enrolled at login.
 *   - If no incode_identity_id exists, the password reset is blocked and the
 *     user is instructed to log in first to establish their identity.
 *   - Only allows the password reset to proceed if auth_overall_status === "OK".
 *   - Verifies the returned identity_id matches the enrolled identity to prevent
 *     identity substitution attacks.
 *
 * Required Secrets (event.secrets):
 *   INCODE_CLIENT_ID      — OIDC client ID (from Incode Workforce dashboard)
 *   INCODE_CLIENT_SECRET  — OIDC client secret (from Incode Workforce dashboard)
 *
 * Required Configuration (event.configuration):
 *   INCODE_AUTH_SERVER    — Incode OIDC auth server base URL
 *                           Demo:       https://auth.demo.incode.com
 *                           Production: https://auth.incode.com
 *   AUTH0_DOMAIN          — Your Auth0 tenant domain (e.g. "your-tenant.us.auth0.com")
 *   SCOPES                — Space-separated OIDC scopes (e.g. "openid")
 *
 * @param {Event} event - Details about the user and the password reset context.
 * @param {PostChallengeAPI} api - Interface whose methods can be used to change the behavior of the flow.
 */

const DEFAULT_AUTH_SERVER = "https://auth.demo.incode.com";

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function exchangeCodeForTokens(code, redirectUri, tokenEndpoint, event) {
  const body = new URLSearchParams({
    grant_type:    "authorization_code",
    code,
    redirect_uri:  redirectUri,
    client_id:     event.secrets.INCODE_CLIENT_ID,
    client_secret: event.secrets.INCODE_CLIENT_SECRET,
  });

  const resp = await fetch(tokenEndpoint, {
    method:  "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept":       "application/json",
    },
    body: body.toString(),
  });

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Incode token exchange failed (${resp.status}): ${err}`);
  }

  return resp.json();
}

/**
 * Verifies the JWT signature of the Incode ID token using the JWKS endpoint.
 *
 * Trust assumption: tokens received directly over TLS from Incode's token
 * endpoint are implicitly trusted per the OIDC spec (section 3.1.3.7).
 * This additional signature verification provides defense-in-depth against
 * token substitution attacks in case the token is intercepted or tampered
 * with before reaching this handler.
 */
async function verifyIdToken(idToken, jwksUri) {
  const jwksResp = await fetch(jwksUri);
  if (!jwksResp.ok) {
    throw new Error(`Failed to fetch JWKS (${jwksResp.status})`);
  }
  const jwks = await jwksResp.json();

  const [headerB64] = idToken.split(".");
  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));

  const jwk = jwks.keys.find(k => k.kid === header.kid);
  if (!jwk) {
    throw new Error(`No matching JWK found for kid: ${header.kid}`);
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const [, payloadB64, signatureB64] = idToken.split(".");
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = Buffer.from(signatureB64, "base64url");

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signature,
    signingInput
  );

  if (!valid) {
    throw new Error("ID token signature verification failed");
  }

  return JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
}

// ─── Main handler ─────────────────────────────────────────────────────────────

exports.onExecutePostChallenge = async (event, api) => {
  // Read non-sensitive values from event.configuration
  const authServer   = event.configuration.INCODE_AUTH_SERVER || DEFAULT_AUTH_SERVER;
  const authEndpoint = `${authServer}/oauth2/authorize`;
  const scopes       = event.configuration.SCOPES || "openid";
  const auth0Domain  = event.configuration.AUTH0_DOMAIN;

  // ── Require prior IDV enrollment ─────────────────────────────────────────
  // The incode_identity_id is stored in app_metadata during the post-login
  // IDV flow. Without it there is no enrolled identity to verify against.
  const identityId = (event.user.app_metadata || {}).incode_identity_id || null;

  if (!identityId) {
    console.error("[Incode Face Auth] No incode_identity_id for user", event.user.user_id);
    return api.access.deny(
      "identity_not_established",
      "You must log in and complete identity verification before resetting your password. Please log in to your account first."
    );
  }

  // ── Build redirect URI ───────────────────────────────────────────────────
  // Register https://<AUTH0_DOMAIN>/continue as an allowed redirect URI
  // in your Incode Workforce OIDC client settings.
  const redirectUri = `https://${auth0Domain}/continue`;

  // ── Build OIDC authorization URL ─────────────────────────────────────────
  // Pass incode_identity_id as login_hint to force a 1:1 Face Auth against
  // the specific legal identity enrolled during post-login IDV.
  // Auth0 manages session state internally — do NOT pass a custom state param.
  const authParams = new URLSearchParams({
    response_type: "code",
    client_id:     event.secrets.INCODE_CLIENT_ID,
    redirect_uri:  redirectUri,
    scope:         scopes,
    login_hint:    identityId,
  });

  console.log("[Incode Face Auth] Redirecting user", event.user.user_id, "for 1:1 Face Auth | identity:", identityId);
  api.redirect.sendUserTo(`${authEndpoint}?${authParams.toString()}`);
};

// ─── Continuation handler ─────────────────────────────────────────────────────

exports.onContinuePostChallenge = async (event, api) => {
  // Read non-sensitive values from event.configuration
  const authServer    = event.configuration.INCODE_AUTH_SERVER || DEFAULT_AUTH_SERVER;
  const tokenEndpoint = `${authServer}/oauth2/token`;
  const jwksUri       = `${authServer}/oauth2/jwks`;
  const auth0Domain   = event.configuration.AUTH0_DOMAIN;
  const redirectUri   = `https://${auth0Domain}/continue`;

  const rawCode  = event.request?.query?.code  || event.request?.body?.code;
  const rawError = event.request?.query?.error || event.request?.body?.error;
  const rawErrorDescription = event.request?.query?.error_description || event.request?.body?.error_description;

  // ── Check for error response from Incode ────────────────────────────────
  if (!rawCode) {
    console.error("[Incode Face Auth] No code returned. Error:", rawError, rawErrorDescription);
    return api.access.deny(
      "face_auth_failed",
      "Identity verification did not complete successfully. Please try again."
    );
  }

  // ── Exchange authorization code for tokens ───────────────────────────────
  let tokenResponse;
  try {
    tokenResponse = await exchangeCodeForTokens(rawCode, redirectUri, tokenEndpoint, event);
  } catch (err) {
    console.error("[Incode Face Auth] Token exchange error:", err.message);
    return api.access.deny(
      "face_auth_failed",
      "Identity verification could not be completed. Please try again."
    );
  }

  // ── Verify ID token signature against Incode's JWKS endpoint ────────────
  // Defense-in-depth: although tokens received directly over TLS from the
  // token endpoint are implicitly trusted per OIDC spec (section 3.1.3.7),
  // we verify the signature to guard against token substitution attacks.
  let idTokenClaims = {};
  try {
    idTokenClaims = await verifyIdToken(tokenResponse.id_token, jwksUri);
  } catch (err) {
    console.error("[Incode Face Auth] ID token verification failed:", err.message);
    return api.access.deny(
      "face_auth_failed",
      "Identity verification result could not be verified. Please try again."
    );
  }

  const authStatus         = idTokenClaims.auth_overall_status || null;
  const authScore          = idTokenClaims.auth_overall_score  || null;
  const returnedIdentityId = idTokenClaims.identity_id         || null;
  const enrolledIdentityId = (event.user.app_metadata || {}).incode_identity_id || null;

  // ── Verify Face Auth passed ──────────────────────────────────────────────
  if (authStatus !== "OK") {
    console.error("[Incode Face Auth] Face Auth failed. Status:", authStatus, "Score:", authScore);
    return api.access.deny(
      "face_auth_failed",
      "Your identity could not be verified. For security reasons your password reset has been blocked. Please contact support."
    );
  }

  // ── Verify identity matches the enrolled identity ────────────────────────
  // Prevents identity substitution attacks by confirming the person completing
  // Face Auth is the same legal identity enrolled during post-login IDV.
  if (returnedIdentityId && enrolledIdentityId && returnedIdentityId !== enrolledIdentityId) {
    console.error("[Incode Face Auth] Identity mismatch! Enrolled:", enrolledIdentityId, "Returned:", returnedIdentityId);
    return api.access.deny(
      "identity_mismatch",
      "The verified identity does not match this account. For security reasons your password reset has been blocked. Please contact support."
    );
  }

  // ── Face Auth passed — allow password reset to proceed ───────────────────
  console.log("[Incode Face Auth] Successful for user", event.user.user_id, "| identity_id:", returnedIdentityId, "| score:", authScore);
};
