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

// ─── Main handler ─────────────────────────────────────────────────────────────

exports.onExecutePostChallenge = async (event, api) => {
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
  const authServer    = event.configuration.INCODE_AUTH_SERVER || DEFAULT_AUTH_SERVER;
  const tokenEndpoint = `${authServer}/oauth2/token`;
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

  // ── Parse ID token claims ────────────────────────────────────────────────
  let idTokenClaims = {};
  try {
    const idTokenPayload = tokenResponse.id_token.split(".")[1];
    idTokenClaims = JSON.parse(Buffer.from(idTokenPayload, "base64url").toString("utf8"));
  } catch (err) {
    console.warn("[Incode Face Auth] ID token parse failed:", err.message);
    return api.access.deny(
      "face_auth_failed",
      "Identity verification result could not be read. Please try again."
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