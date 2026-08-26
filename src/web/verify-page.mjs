import trustModel from "../../config/trust-roots.json";
import { analyzeClaimInBrowser } from "./verifier-client.mjs";

const form = document.querySelector("#verify-form");
const input = document.querySelector("#claim-input");
const analyzeButton = document.querySelector("#analyze-button");
const clearButton = document.querySelector("#clear-button");
const dataState = document.querySelector("#data-state");
const characterCount = document.querySelector("#character-count");
const resultPlaceholder = document.querySelector("#result-placeholder");
const resultContent = document.querySelector("#result-content");
const verdictBanner = document.querySelector("#verdict-banner");
const verdictTitle = document.querySelector("#verdict-title");
const verdictConfidence = document.querySelector("#verdict-confidence");
const verdictSummary = document.querySelector("#verdict-summary");
const indicatorList = document.querySelector("#indicator-list");
const urlGroup = document.querySelector("#url-group");
const urlList = document.querySelector("#url-list");
const evidenceGroup = document.querySelector("#evidence-group");
const evidenceList = document.querySelector("#evidence-list");
const limitationList = document.querySelector("#limitation-list");
const resultDataset = document.querySelector("#result-dataset");
const copyResult = document.querySelector("#copy-result");

let statusDocument = null;
let latestResult = null;

const text = {
  ja: {
    ready: "証拠データ読込済み",
    loadError: "証拠データを読み込めません",
    empty: "検証する内容を入力してください。",
    analyzing: "検証中…",
    reasons: "判定理由",
    urls: "検出URL",
    evidence: "根拠",
    limits: "この判定の限界",
    noIndicator: "設定済みの危険指標は検出されませんでした。",
    dataset: "使用データ",
    copied: "コピーしました",
    copyFailed: "コピーできませんでした",
    verdicts: {
      VERIFIED_OFFICIAL_ROOT: "公式rootと一致",
      OFFICIALLY_REFERENCED: "公式namespace／参照先",
      UNVERIFIED: "未確認",
      CONFLICTS_WITH_CURRENT_OFFICIAL_STATE: "現行仕様と矛盾",
      HIGH_RISK_PATTERN: "高リスク指標あり",
    },
    summaries: {
      VERIFIED_OFFICIAL_ROOT: "入力は固定した公式rootと完全一致し、設定済みの危険指標は検出されませんでした。",
      OFFICIALLY_REFERENCED: "入力は設定済みの公式namespaceまたは公式参照先に含まれます。内容そのものの正しさは別途確認してください。",
      UNVERIFIED: "現在の証拠だけでは、公式または安全として扱えません。これは詐欺の断定ではありません。",
      CONFLICTS_WITH_CURRENT_OFFICIAL_STATE: "主張の一部が、現在観測している公式仕様と矛盾します。",
      HIGH_RISK_PATTERN: "操作を止め、別経路で確認すべき高リスク指標があります。",
    },
  },
  en: {
    ready: "Evidence dataset ready",
    loadError: "Evidence dataset failed to load",
    empty: "Enter something to verify.",
    analyzing: "Checking…",
    reasons: "Reasons",
    urls: "Detected URLs",
    evidence: "Evidence",
    limits: "Limits of this verdict",
    noIndicator: "No configured risk indicator was triggered.",
    dataset: "Dataset",
    copied: "Copied",
    copyFailed: "Copy failed",
    verdicts: {
      VERIFIED_OFFICIAL_ROOT: "Verified official root",
      OFFICIALLY_REFERENCED: "Official namespace / reference",
      UNVERIFIED: "Unverified",
      CONFLICTS_WITH_CURRENT_OFFICIAL_STATE: "Conflicts with current state",
      HIGH_RISK_PATTERN: "High-risk pattern",
    },
    summaries: {
      VERIFIED_OFFICIAL_ROOT: "The input exactly matches a pinned official root and no configured risk indicator was detected.",
      OFFICIALLY_REFERENCED: "The input is inside a configured official namespace or reference. Its specific content still needs review.",
      UNVERIFIED: "The current evidence is insufficient to treat this as official or safe. This is not an accusation of fraud.",
      CONFLICTS_WITH_CURRENT_OFFICIAL_STATE: "Part of the claim conflicts with the currently observed official specification.",
      HIGH_RISK_PATTERN: "Stop and verify through another channel before taking action.",
    },
  },
};

const indicatorText = {
  INVALID_URL: ["URLを解析できません。", "The URL could not be parsed."],
  INSECURE_HTTP: ["HTTPSではありません。", "The URL does not use HTTPS."],
  URL_USERINFO: ["userinfo構文で実際のhostが隠されています。", "User-info syntax hides the actual host."],
  NON_STANDARD_PORT: ["標準外のportを使用しています。", "The URL uses a non-standard port."],
  IP_LITERAL_HOST: ["ドメインではなくIPアドレスが指定されています。", "The URL uses an IP address instead of a named host."],
  PUNYCODE_HOST: ["Punycodeによる類似文字の可能性があります。", "Punycode may visually imitate another domain."],
  MIXED_SCRIPT_HOST: ["ラテン文字とキリル／ギリシャ文字が混在しています。", "The hostname mixes Latin with Cyrillic or Greek characters."],
  EMBEDDED_OFFICIAL_HOSTNAME: ["公式host名が別ドメインの一部として埋め込まれています。", "An official hostname is embedded inside another parent domain."],
  LOOKALIKE_OFFICIAL_HOSTNAME: ["公式host名に非常によく似ています。", "The hostname is very close to an official host."],
  USER_WRITABLE_OFFICIAL_SERVICE: ["公式サービス上ですが、第三者が書き込める領域です。", "This is on an official service but inside a user-writable area."],
  UNVERIFIED_URL: ["設定済みの公式rootでは確認できません。", "The URL is not covered by a configured official root."],
  SECRET_MATERIAL_REQUEST: ["秘密鍵・seed・復元フレーズを要求しています。絶対に入力しないでください。", "It requests a private key, seed, or recovery phrase. Never enter one."],
  WALLET_CONNECTION_REQUEST: ["ウォレット接続を要求しています。originと署名内容を確認してください。", "It requests a wallet connection. Verify the origin and signature request."],
  UNVERIFIED_CONTRACT_ADDRESS: ["現在の公式データに掲載されていないアドレスです。", "The address is not in the current official dataset."],
  CLAIM_CONFLICTS_WITH_CURRENT_SERVICE: ["Technocoreのclaimを主張していますが、現行仕様にはclaim/token endpointがありません。", "It associates a claim with Technocore, whose current specification has no claim/token endpoint."],
};

function language() {
  return document.documentElement.dataset.language === "en" ? "en" : "ja";
}

function clearChildren(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function createTextElement(tag, value, className = null) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = value;
  return element;
}

function safeEvidenceLink(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" ? parsed.href : null;
  } catch {
    return null;
  }
}

function renderResult() {
  if (!latestResult) return;
  const selected = language();
  const copy = text[selected];
  resultPlaceholder.hidden = true;
  resultContent.hidden = false;
  verdictBanner.dataset.verdict = latestResult.verdict;
  verdictTitle.textContent = copy.verdicts[latestResult.verdict] ?? latestResult.verdict;
  verdictConfidence.textContent = `${latestResult.confidence.toUpperCase()} CONFIDENCE`;
  verdictSummary.textContent = copy.summaries[latestResult.verdict] ?? latestResult.summary;
  document.querySelector("#indicator-heading").textContent = copy.reasons;
  document.querySelector("#url-heading").textContent = copy.urls;
  document.querySelector("#evidence-heading").textContent = copy.evidence;
  document.querySelector("#limitation-heading").textContent = copy.limits;

  clearChildren(indicatorList);
  if (latestResult.indicators.length === 0) {
    const item = createTextElement("li", copy.noIndicator, "indicator-item");
    item.dataset.severity = "info";
    indicatorList.append(item);
  } else {
    for (const indicator of latestResult.indicators) {
      const item = document.createElement("li");
      item.className = "indicator-item";
      item.dataset.severity = indicator.severity;
      item.append(createTextElement("strong", `${indicator.severity.toUpperCase()} · ${indicator.code}`));
      item.append(createTextElement("p", indicatorText[indicator.code]?.[selected === "ja" ? 0 : 1] ?? indicator.message));
      indicatorList.append(item);
    }
  }

  clearChildren(urlList);
  urlGroup.hidden = latestResult.urls.length === 0;
  for (const url of latestResult.urls) {
    const item = document.createElement("li");
    item.className = "url-result-item";
    item.append(createTextElement("strong", url.normalized ?? url.input));
    item.append(createTextElement("p", `${url.classification} · ${url.hostname ?? "invalid"}`));
    urlList.append(item);
  }

  clearChildren(evidenceList);
  evidenceGroup.hidden = latestResult.evidence.length === 0;
  for (const evidence of latestResult.evidence) {
    const item = document.createElement("li");
    const href = safeEvidenceLink(evidence.url);
    if (href) {
      const link = document.createElement("a");
      link.href = href;
      link.target = "_blank";
      link.rel = "noreferrer";
      link.textContent = `${evidence.sourceId} ↗`;
      item.append(link);
    } else {
      item.textContent = evidence.sourceId;
    }
    evidenceList.append(item);
  }

  clearChildren(limitationList);
  const limits = selected === "ja"
    ? [
      "この判定は安全を保証しません。",
      "入力されたURLの現在のページ内容は取得していません。",
      "データ時刻以降に公式情報が変わっている可能性があります。",
    ]
    : latestResult.limitations;
  for (const limitation of limits) limitationList.append(createTextElement("li", limitation));
  resultDataset.textContent = `${copy.dataset}: ${latestResult.datasetGeneratedAt} · SHA-256 ${latestResult.input.sha256}`;
}

async function loadStatus() {
  try {
    const response = await fetch(new URL("../status.json", window.location.href), {
      headers: { accept: "application/json" },
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    statusDocument = await response.json();
    if (statusDocument.schemaVersion !== 1) throw new Error("schema mismatch");
    analyzeButton.disabled = false;
    dataState.replaceChildren(createTextElement("span", text[language()].ready));
  } catch {
    dataState.replaceChildren(createTextElement("span", text[language()].loadError));
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!statusDocument) return;
  if (!input.value.trim()) {
    input.setCustomValidity(text[language()].empty);
    input.reportValidity();
    return;
  }
  input.setCustomValidity("");
  analyzeButton.disabled = true;
  analyzeButton.setAttribute("aria-busy", "true");
  try {
    latestResult = await analyzeClaimInBrowser(input.value, { trustModel, statusDocument });
    renderResult();
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.removeAttribute("aria-busy");
  }
});

input.addEventListener("input", () => {
  input.setCustomValidity("");
  characterCount.textContent = String([...input.value].length);
});

for (const button of document.querySelectorAll("[data-example]")) {
  button.addEventListener("click", () => {
    input.value = button.dataset.example;
    input.dispatchEvent(new Event("input"));
    input.focus();
  });
}

clearButton.addEventListener("click", () => {
  input.value = "";
  input.dispatchEvent(new Event("input"));
  latestResult = null;
  resultContent.hidden = true;
  resultPlaceholder.hidden = false;
  input.focus();
});

copyResult.addEventListener("click", async () => {
  if (!latestResult) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(latestResult, null, 2));
    copyResult.title = text[language()].copied;
  } catch {
    copyResult.title = text[language()].copyFailed;
  }
});

window.addEventListener("flop-language-change", () => {
  if (statusDocument) dataState.replaceChildren(createTextElement("span", text[language()].ready));
  renderResult();
});

loadStatus();
