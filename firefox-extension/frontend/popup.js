const didServiceUrl = "http://127.0.0.1:8765";

const didNameInput = document.getElementById("did-name");
const didList = document.getElementById("did-list");
const didAlias = document.getElementById("did-alias");
const createButton = document.getElementById("create-did");
const copyButton = document.getElementById("copy-did");
const statusText = document.getElementById("status");
let didRecords = [];

function setStatus(message) {
  statusText.textContent = message;
}

// searches for selected did in the list didRecords and returns its data
function selectedRecord() {
  return didRecords.find((record) => record.did === didList.value);
}

// saves currently selected did and informs backend
function storeSelectedRecord() {
  const record = selectedRecord();
  const did = record ? record.did : "";

  copyButton.disabled = !record;
  browser.storage.local.set({ selectedDid: did });

  fetch(`${didServiceUrl}/wallet/selected-did`, {
    method: "POST",
    headers: {
      "Accept": "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ did })
  }).catch(console.error);
}

// renders list of dids from backend
function renderDids(records, selectedDid = didList.value) {
  didRecords = records;
  didList.textContent = "";

  for (const record of didRecords) {
    const option = document.createElement("option");
    option.value = record.did;
    option.textContent = record.name;
    didList.append(option);
  }

  didList.value = selectedDid;
  storeSelectedRecord();
}

// requests json file containing dids from backend service
async function loadDids(selectedDid) {
  const response = await fetch(`${didServiceUrl}/dids`, {
    headers: {
      "Accept": "application/json"
    }
  });

  if (!response.ok) {
    throw new Error(`DID service returned ${response.status}`);
  }

  renderDids(await response.json(), selectedDid);
}

// requests a new did to be generated at the backend service
async function generateDid() {
  const name = didNameInput.value.trim();

  if (!name) {
    didNameInput.focus();
    throw new Error("Missing DID name");
  }

  const response = await fetch(`${didServiceUrl}/create-did`, {
    method: "POST",
    headers: {
      "Accept": "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ name })
  });

  if (!response.ok) {
    throw new Error(`DID service returned ${response.status}`);
  }

  const record = await response.json();
  return record;
}

createButton.addEventListener("click", async () => {
  createButton.disabled = true;
  setStatus("Sending request to local DID-Service...");

  try {
    const record = await generateDid();
    await loadDids(record.did);
    didNameInput.value = "";
    setStatus(`DID fuer "${record.name}" wurde erstellt.`);
  } catch (error) {
    console.error(error);
    setStatus(error.message === "Missing DID name" ? "Please enter an alias fro your DID." : "DID-Service not responding or has an error.");
  } finally {
    createButton.disabled = false;
  }
});

copyButton.addEventListener("click", async () => {
  const record = selectedRecord();

  if (!record) {
    return;
  }

  await navigator.clipboard.writeText(record.did);
  setStatus(`Vollstaendige DID fuer "${record.name}" kopiert.`);
});

didList.addEventListener("change", () => {
  storeSelectedRecord();
});

async function initializePopup() {
  await loadDids("");
  setStatus("Wallet geladen.");
}

initializePopup().catch((error) => {
  console.error(error);
  copyButton.disabled = true;
  setStatus("DID-Service nicht erreichbar.");
});