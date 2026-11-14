const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const backgroundSource = readFileSync(
  path.join(__dirname, "../firefox-extension/background.js"),
  "utf8"
);
const RP_ORIGIN = "http://127.0.0.1:3002";
const IDP_ORIGIN = "https://127.0.0.1:3001";
const USER_DID = "did:peer:test-user";
const flushAsyncWork = () => new Promise(setImmediate);

async function createExtension({ knownIdpOrigins = [] } = {}) {
  const listeners = {};
  const requests = [];
  const storage = {
    selectedDid: USER_DID,
    automaticDidManagement: true,
    knownIdpOrigins,
  };
  const event = (name) => ({
    addListener(listener) {
      listeners[name] = listener;
    },
  });
  const browser = {
    storage: {
      local: {
        async get() { return { ...storage }; },
        async set(values) { Object.assign(storage, values); },
        async remove(key) { delete storage[key]; },
      },
      onChanged: event("storageChanged"),
    },
    webRequest: {
      onCompleted: event("completed"),
      onBeforeSendHeaders: event("beforeSendHeaders"),
      onHeadersReceived: event("headersReceived"),
    },
    tabs: {
      async get() { return { url: RP_ORIGIN }; },
    },
  };
  const context = vm.createContext({
    browser,
    URL,
    console,
    setTimeout,
    clearTimeout,
    async fetch(url, options = {}) {
      const requestPath = new URL(url).pathname;
      requests.push({ path: requestPath, options });
      let result;
      switch (requestPath) {
        case "/evaluation/measurements":
          result = { enabled: false };
          break;
        case "/wallet/prepare-for-rp":
        case "/wallet/select-for-service":
          result = { selectedDid: { did: USER_DID } };
          break;
        case "/sso/current-auth-request":
          result = { sessionId: "test-session", state: "test-state" };
          break;
        default:
          throw new Error(`Unexpected backend request: ${requestPath}`);
      }
      return { ok: true, async json() { return result; } };
    },
  });
  vm.runInContext(backgroundSource, context, { filename: "background.js" });
  await flushAsyncWork();
  requests.length = 0;
  return { listeners, requests, storage };
}

function outgoingRequest(url, method = "POST") {
  return {
    url,
    method,
    tabId: 7,
    originUrl: `${RP_ORIGIN}/did-sso`,
    requestHeaders: [{ name: "Content-Type", value: "application/json" }],
  };
}

for (const [name, url, knownIdpOrigins] of [
  ["an unknown local service", "http://127.0.0.1:4000/register", []],
  ["an unrecognized IdP", `${IDP_ORIGIN}/register`, []],
  ["a recognized IdP", `${IDP_ORIGIN}/register`, [IDP_ORIGIN]],
]) {
  test(`ordinary registration at ${name} does not invoke DID handling`, async () => {
    const extension = await createExtension({ knownIdpOrigins });
    const request = outgoingRequest(url);
    const result = await extension.listeners.beforeSendHeaders(request);
    assert.equal(Object.keys(result).length, 0);
    assert.equal(extension.requests.length, 0);
    assert.equal(request.requestHeaders.length, 1);
  });
}

test("starting SSO prepares the RP DID and attaches exactly one DID header", async () => {
  const extension = await createExtension();
  const request = outgoingRequest("http://127.0.0.1:8771/sso/start");
  request.requestHeaders.push({ name: "x-didsso-did", value: "old-did" });
  const result = await extension.listeners.beforeSendHeaders(request);
  const didHeaders = result.requestHeaders.filter(
    (header) => header.name.toLowerCase() === "x-didsso-did"
  );
  assert.equal(didHeaders.length, 1);
  assert.equal(didHeaders[0].value, USER_DID);
  assert.equal(extension.requests.length, 1);
  assert.equal(extension.requests[0].path, "/wallet/prepare-for-rp");
  assert.equal(JSON.parse(extension.requests[0].options.body).rpOrigin, RP_ORIGIN);
});

test("direct login selects a bound DID without requesting DID preparation", async () => {
  const extension = await createExtension();
  const result = await extension.listeners.beforeSendHeaders(
    outgoingRequest("http://127.0.0.1:8771/did-login/start")
  );
  assert.equal(
    result.requestHeaders.find((header) => header.name === "X-DIDSSO-DID").value,
    USER_DID
  );
  assert.equal(extension.requests.length, 1);
  assert.equal(extension.requests[0].path, "/wallet/select-for-service");
});

for (const [url, method] of [
  ["http://127.0.0.1:8771/sso/start", "GET"],
  ["http://127.0.0.1:8771/logout", "POST"],
  ["https://example.com/sso/start", "POST"],
]) {
  test(`${method} ${url} does not invoke DID handling`, async () => {
    const extension = await createExtension();
    const result = await extension.listeners.beforeSendHeaders(outgoingRequest(url, method));
    assert.equal(Object.keys(result).length, 0);
    assert.equal(extension.requests.length, 0);
  });
}

test("the IdP service header still initializes the browser-side SSO context", async () => {
  const extension = await createExtension();
  extension.listeners.headersReceived({
    url: `${IDP_ORIGIN}/sso`,
    type: "main_frame",
    tabId: 7,
    responseHeaders: [{ name: "X-DIDSSO-Service", value: "idp" }],
  });
  await flushAsyncWork();
  assert.equal(extension.storage.activeSsoAuthentication.tabId, 7);
  assert.equal(extension.storage.activeSsoAuthentication.origin, IDP_ORIGIN);
  assert.equal(extension.storage.activeSsoAuthentication.sessionId, "test-session");
  assert.equal(extension.storage.activeSsoAuthentication.state, "test-state");
  assert.ok(extension.storage.knownIdpOrigins.includes(IDP_ORIGIN));
});

test("navigation to a recognized IdP still skips RP-related DID selection", async () => {
  const extension = await createExtension({ knownIdpOrigins: [IDP_ORIGIN] });
  extension.listeners.completed({ url: `${IDP_ORIGIN}/login`, type: "main_frame" });
  await flushAsyncWork();
  assert.equal(extension.requests.length, 0);
});
