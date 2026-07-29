const DID_HEADER = "X-DIDSSO-DID";
const DIDSSO_CODE_HEADER = "X-DIDSSO-Code";
const DIDSSO_MESSAGE_TYPE_HEADER = "X-DIDSSO-Message-Type";
const DIDSSO_SERVICE_HEADER = "X-DIDSSO-Service";
const DIDSSO_REPLACE_ID_HEADER = "X-DIDSSO-Replace-ID";
const REGISTER_PATH = "/register";
const DID_SERVICE_URL = "http://127.0.0.1:8765";

let selectedDid = "";
let automaticDidManagement = true;
let activeSsoAuthentication = null;
let knownIdpOrigins = new Set();

const managementSettingsReady = browser.storage.local
  .get([
    "selectedDid",
    "automaticDidManagement",
    "activeSsoAuthentication",
    "knownIdpOrigins"
  ])
  .then((stored) => {
    selectedDid = stored.selectedDid || "";
    automaticDidManagement = stored.automaticDidManagement !== false;
    activeSsoAuthentication = stored.activeSsoAuthentication || null;
    knownIdpOrigins = new Set([
      ...knownIdpOrigins,
      ...(stored.knownIdpOrigins || [])
    ]);
  });

// Loads the selected DID from browser storage or restores it from the backend.
async function restoreSelectedDid() {
  await managementSettingsReady;

  if (selectedDid) {
    return selectedDid;
  }

  const stored = await browser.storage.local.get("selectedDid");
  selectedDid = stored.selectedDid || "";

  if (selectedDid) {
    return selectedDid;
  }

  try {
    const response = await fetch(`${DID_SERVICE_URL}/sso/selected-did`, {
      headers: {
        "Accept": "application/json"
      }
    });

    if (response.ok) {
      const record = await response.json();
      selectedDid = record.did || "";

      if (selectedDid) {
        await browser.storage.local.set({ selectedDid });
      }
    }
  } catch (error) {
    console.warn("Could not restore selected DID from backend", error);
  }

  return selectedDid;
}

restoreSelectedDid();

// reacts to changes of selected did
browser.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") {
    return;
  }

  if (changes.selectedDid) {
    selectedDid = changes.selectedDid.newValue || "";
  }

  if (changes.automaticDidManagement) {
    automaticDidManagement =
      changes.automaticDidManagement.newValue !== false;
  }
});

// Selects or creates a DID when navigating between different services.
async function selectDidForService(origin) {
  await managementSettingsReady;

  if (!automaticDidManagement) {
    return;
  }

  if (!origin || origin === DID_SERVICE_URL) {
    return;
  }

  try {
    const response = await fetch(`${DID_SERVICE_URL}/wallet/select-for-service`, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ serviceOrigin: origin })
    });
    const data = await response.json();

    if (response.ok && data.selectedDid) {
      selectedDid = data.selectedDid.did;
      await browser.storage.local.set({ selectedDid });
    }
  } catch (error) {
    console.warn("Could not select DID for current service", error);
  }
}

async function prepareDidForRp(origin) {
  await managementSettingsReady;

  const manualDid = automaticDidManagement
    ? ""
    : await restoreSelectedDid();
  const response = await fetch(`${DID_SERVICE_URL}/wallet/prepare-for-rp`, {
    method: "POST",
    headers: {
      "Accept": "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      rpOrigin: origin,
      automatic: automaticDidManagement,
      selectedDid: manualDid
    })
  });
  const data = await response.json();

  if (!response.ok || !data.selectedDid?.did) {
    throw new Error(data.error || "No DID is available for this RP");
  }

  selectedDid = data.selectedDid.did;
  await browser.storage.local.set({ selectedDid });
  return selectedDid;
}

function headerValue(headers, name) {
  const header = (headers || []).find(
    (item) => item.name.toLowerCase() === name.toLowerCase()
  );
  return header?.value || "";
}

async function rememberIdpOrigin(origin) {
  await managementSettingsReady;
  knownIdpOrigins.add(origin);
  await browser.storage.local.set({
    knownIdpOrigins: Array.from(knownIdpOrigins)
  });
}

async function beginSsoAuthentication(details, origin) {
  try {
    const response = await fetch(`${DID_SERVICE_URL}/sso/current-challenge`, {
      headers: {"Accept": "application/json"}
    });
    const challenge = await response.json();

    if (!response.ok || !challenge.sessionId) {
      return;
    }

    activeSsoAuthentication = {
      tabId: details.tabId,
      origin,
      sessionId: challenge.sessionId
    };
    await browser.storage.local.set({activeSsoAuthentication});
  } catch (error) {
    console.warn("Could not start the HTTPS authorization-code phase", error);
  }
}

async function clearSsoAuthentication() {
  activeSsoAuthentication = null;
  await browser.storage.local.remove("activeSsoAuthentication");
}

async function handleAuthorizationCodeResponse(details) {
  await managementSettingsReady;

  const url = new URL(details.url);
  const messageType = headerValue(
    details.responseHeaders,
    DIDSSO_MESSAGE_TYPE_HEADER
  );
  const code = headerValue(details.responseHeaders, DIDSSO_CODE_HEADER);

  if (
    details.statusCode < 200 ||
    details.statusCode >= 300 ||
    url.pathname !== "/sso/issue-code" ||
    messageType !== "authorization-code" ||
    !code
  ) {
    return;
  }

  const context = activeSsoAuthentication;
  if (
    !context ||
    context.tabId !== details.tabId ||
    context.origin !== url.origin
  ) {
    console.error(
      "DIDSSO authorization code rejected because it does not match the active authentication tab and origin"
    );
    return;
  }

  try {
    const tab = await browser.tabs.get(details.tabId);
    if (!tab.url || new URL(tab.url).origin !== context.origin) {
      throw new Error(
        "The authentication tab changed its origin before the code was processed"
      );
    }

    const response = await fetch(`${DID_SERVICE_URL}/sso/authorization-code`, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        code,
        replaceId: headerValue(
          details.responseHeaders,
          DIDSSO_REPLACE_ID_HEADER
        ),
        authenticationOrigin: context.origin,
        sessionId: context.sessionId
      })
    });
    const data = await response.json();

    if (!response.ok || !data.redirectUrl) {
      throw new Error(data.error || "Authorization code could not be forwarded");
    }

    await clearSsoAuthentication();
    await browser.tabs.update(details.tabId, {url: data.redirectUrl});
  } catch (error) {
    console.error("Could not process HTTPS DIDSSO authorization code", error);
  }
}

browser.webRequest.onCompleted.addListener(
  (details) => {
    const url = new URL(details.url);

    if (url.hostname !== "127.0.0.1") {
      return;
    }

    if (knownIdpOrigins.has(url.origin)) {
      return;
    }

    selectDidForService(url.origin);
  },
  { urls: ["http://127.0.0.1/*", "https://127.0.0.1/*"], types: ["main_frame"] }
);

// adds did header to register request at IdP
browser.webRequest.onBeforeSendHeaders.addListener(
  async (details) => {
    const url = new URL(details.url);

    if (
      details.method !== "POST" ||
      url.hostname !== "127.0.0.1" ||
      url.pathname !== REGISTER_PATH
    ) {
      return {};
    }

    await managementSettingsReady;
    if (knownIdpOrigins.has(url.origin)) {
      return {};
    }

    try {
      await prepareDidForRp(url.origin);
    } catch (error) {
      console.error("DID registration request blocked", error);
      return { cancel: true };
    }

    const requestHeaders = details.requestHeaders.filter(
      (header) => header.name.toLowerCase() !== DID_HEADER.toLowerCase()
    );

    requestHeaders.push({
      name: DID_HEADER,
      value: selectedDid,
    });

    return { requestHeaders };
  },
  { urls: ["http://127.0.0.1/*", "https://127.0.0.1/*"], types: ["main_frame", "xmlhttprequest"] },
  ["blocking", "requestHeaders"]
);

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const url = new URL(details.url);
    const isIdp =
      headerValue(details.responseHeaders, DIDSSO_SERVICE_HEADER) === "idp";

    if (isIdp) {
      knownIdpOrigins.add(url.origin);
      rememberIdpOrigin(url.origin).catch((error) => {
        console.warn("Could not persist the IdP origin", error);
      });

      if (details.type === "main_frame" && url.pathname === "/sso") {
        beginSsoAuthentication(details, url.origin);
      }
    }

    handleAuthorizationCodeResponse(details);
  },
  {urls: ["https://127.0.0.1/*"]},
  ["responseHeaders"]
);
