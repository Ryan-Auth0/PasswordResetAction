const { onExecutePostChallenge, onContinuePostChallenge } = require("./integration.action");

const mockApi = {
  access: { deny: jest.fn() },
  redirect: { sendUserTo: jest.fn() },
};

const mockEvent = {
  user: {
    user_id: "auth0|123",
    email: "test@example.com",
    app_metadata: {
      incode_identity_id: "test-identity-id",
    },
  },
  request: {
    query: {},
    body: {},
  },
  secrets: {
    INCODE_CLIENT_ID: "test-client-id",
    INCODE_CLIENT_SECRET: "test-client-secret",
  },
  configuration: {
    INCODE_AUTH_SERVER: "https://auth.demo.incode.com",
    AUTH0_DOMAIN: "test.us.auth0.com",
    SCOPES: "openid",
  },
};

beforeEach(() => {
  jest.clearAllMocks();
});

describe("onExecutePostChallenge", () => {
  it("redirects user to Incode Face Auth when identity exists", async () => {
    await onExecutePostChallenge(mockEvent, mockApi);
    expect(mockApi.redirect.sendUserTo).toHaveBeenCalledWith(
      expect.stringContaining("https://auth.demo.incode.com/oauth2/authorize")
    );
  });

  it("passes identity_id as login_hint", async () => {
    await onExecutePostChallenge(mockEvent, mockApi);
    expect(mockApi.redirect.sendUserTo).toHaveBeenCalledWith(
      expect.stringContaining("login_hint=test-identity-id")
    );
  });

  it("denies access when no incode_identity_id exists", async () => {
    const eventWithoutIdentity = {
      ...mockEvent,
      user: {
        ...mockEvent.user,
        app_metadata: {},
      },
    };
    await onExecutePostChallenge(eventWithoutIdentity, mockApi);
    expect(mockApi.access.deny).toHaveBeenCalledWith(
      "identity_not_established",
      expect.any(String)
    );
    expect(mockApi.redirect.sendUserTo).not.toHaveBeenCalled();
  });
});

describe("onContinuePostChallenge", () => {
  it("denies access when no code is returned", async () => {
    const eventWithError = {
      ...mockEvent,
      request: {
        query: { error: "access_denied", error_description: "User cancelled" },
        body: {},
      },
    };
    await onContinuePostChallenge(eventWithError, mockApi);
    expect(mockApi.access.deny).toHaveBeenCalledWith(
      "face_auth_failed",
      expect.any(String)
    );
  });
});
