const DID_HEADER = "X-DIDSSO-DID";
const REGISTER_PATH = "/register";
const DID_SERVICE_URL = "http://127.0.0.1:8765";

let selectedDid = "";

// loads last selected did from browser storage
browser.storage.local.get("selectedDid").then((result) => {
  selectedDid = result.selectedDid || "";
});

// reacts to changes of selected did
browser.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes.selectedDid) {
    selectedDid = changes.selectedDid.newValue || "";
  }
});
// requests if a DID exists which is bounded to the visited RP, it will be selected
async function selectBoundDidForRp(origin) {
  if (!origin || origin === DID_SERVICE_URL) {
    return;
  }

  try {
    const response = await fetch(`${DID_SERVICE_URL}/wallet/select-for-rp`, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ rpOrigin: origin })
    });
    const data = await response.json();

    if (response.ok && data.status === "selected" && data.selectedDid) {
      selectedDid = data.selectedDid.did;
      await browser.storage.local.set({ selectedDid });
    }
  } catch (error) {
    console.warn("Could not auto-select bound DID for RP", error);
  }
}

browser.webRequest.onCompleted.addListener(
  (details) => {
    const url = new URL(details.url);

    if (url.hostname !== "127.0.0.1") {
      return;
    }

    selectBoundDidForRp(url.origin);
  },
  { urls: ["http://127.0.0.1/*", "https://127.0.0.1/*"], types: ["main_frame"] }
);

// adds did header to register request at IdP
browser.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const url = new URL(details.url);

    if (
      details.method !== "POST" ||
      url.hostname !== "127.0.0.1" ||
      url.pathname !== REGISTER_PATH ||
      !selectedDid
    ) {
      return {};
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
