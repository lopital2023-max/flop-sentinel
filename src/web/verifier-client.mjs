const SECRET_REQUEST = /(?:private[\s_-]*key|seed[\s_-]*phrase|recovery[\s_-]*phrase|mnemonic|秘密鍵|シード(?:フレーズ)?|復元フレーズ|ニーモニック)/iu;
const CLAIM_LANGUAGE = /(?:\bclaim\b|\bfaucet\b|\bairdrop\b|エアドロップ|エアドロ|トークン.{0,20}(?:受け取|受取|請求)|無料.{0,12}トークン)/iu;
const WALLET_CONNECT = /(?:connect[\s_-]*(?:your[\s_-]*)?wallet|wallet[\s_-]*connect|ウォレット.{0,10}(?:接続|連携))/iu;
const ADDRESS_PATTERN = /\b0x[a-fA-F0-9]{40}\b/g;
const URL_PATTERN = /https?:\/\/[^\s<>"'`）)\]}]+/giu;
const TRAILING_URL_PUNCTUATION = /[.,;:!?。、「」』】]+$/u;

function canonicalUrl(url) {
  const candidate = new URL(url);
  candidate.hash = "";
  return candidate;
}

function pathMatchesPrefix(candidatePath, rootPath) {
  const normalizedRoot = rootPath.endsWith("/") && rootPath !== "/"
    ? rootPath.slice(0, -1)
    : rootPath;
  return candidatePath === normalizedRoot || candidatePath.startsWith(`${normalizedRoot}/`);
}

function matchingRoot(candidate, trustModel) {
  for (const root of trustModel.roots) {
    const rootUrl = canonicalUrl(root.url);
    if (candidate.origin !== rootUrl.origin) continue;
    if (root.scope === "exact-url" && candidate.href === rootUrl.href) return root;
    if (root.scope === "path-prefix" && pathMatchesPrefix(candidate.pathname, rootUrl.pathname)) {
      return root;
    }
  }
  return null;
}

function matchingUntrustedZone(candidate, trustModel) {
  return (trustModel.untrustedHostedZones ?? []).find(
    (zone) => candidate.origin === zone.origin && candidate.pathname.startsWith(zone.pathPrefix),
  ) ?? null;
}

function levenshtein(left, right) {
  let previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let leftIndex = 1; leftIndex <= left.length; leftIndex += 1) {
    const current = [leftIndex];
    for (let rightIndex = 1; rightIndex <= right.length; rightIndex += 1) {
      current[rightIndex] = Math.min(
        current[rightIndex - 1] + 1,
        previous[rightIndex] + 1,
        previous[rightIndex - 1] + (left[leftIndex - 1] === right[rightIndex - 1] ? 0 : 1),
      );
    }
    previous = current;
  }
  return previous[right.length];
}

function isIpLiteral(hostname) {
  if (hostname.includes(":")) return true;
  const pieces = hostname.split(".");
  return pieces.length === 4 && pieces.every(
    (piece) => /^\d{1,3}$/.test(piece) && Number(piece) <= 255,
  );
}

function punycodeDigit(character) {
  const code = character.codePointAt(0);
  if (code >= 48 && code <= 57) return code - 22;
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 97;
  throw new Error("invalid Punycode digit");
}

function adaptPunycodeBias(delta, pointCount, firstInsertion) {
  let adjusted = firstInsertion ? Math.floor(delta / 700) : Math.floor(delta / 2);
  adjusted += Math.floor(adjusted / pointCount);
  let scale = 0;
  while (adjusted > 455) {
    adjusted = Math.floor(adjusted / 35);
    scale += 36;
  }
  return scale + Math.floor((36 * adjusted) / (adjusted + 38));
}

function decodePunycodeLabel(label) {
  const input = label.slice(4).toLowerCase();
  const output = [];
  const delimiter = input.lastIndexOf("-");
  let cursor = 0;
  if (delimiter >= 0) {
    for (const character of input.slice(0, delimiter)) output.push(character.codePointAt(0));
    cursor = delimiter + 1;
  }
  let codePoint = 128;
  let insertion = 0;
  let bias = 72;
  while (cursor < input.length) {
    const previousInsertion = insertion;
    let weight = 1;
    for (let thresholdIndex = 36; ; thresholdIndex += 36) {
      if (cursor >= input.length) throw new Error("truncated Punycode label");
      const digit = punycodeDigit(input[cursor]);
      cursor += 1;
      insertion += digit * weight;
      const threshold = thresholdIndex <= bias ? 1 : thresholdIndex >= bias + 26 ? 26 : thresholdIndex - bias;
      if (digit < threshold) break;
      weight *= 36 - threshold;
    }
    const pointCount = output.length + 1;
    bias = adaptPunycodeBias(insertion - previousInsertion, pointCount, previousInsertion === 0);
    codePoint += Math.floor(insertion / pointCount);
    insertion %= pointCount;
    output.splice(insertion, 0, codePoint);
    insertion += 1;
  }
  return String.fromCodePoint(...output);
}

function unicodeHostname(hostname) {
  return hostname.split(".").map((label) => {
    if (!label.startsWith("xn--")) return label;
    try {
      return decodePunycodeLabel(label);
    } catch {
      return label;
    }
  }).join(".");
}

function hasMixedConfusableScripts(hostname) {
  const decoded = unicodeHostname(hostname);
  return /\p{Script=Latin}/u.test(decoded) &&
    (/\p{Script=Cyrillic}/u.test(decoded) || /\p{Script=Greek}/u.test(decoded));
}

function indicator(code, severity, message, subject = null) {
  return { code, severity, message, ...(subject ? { subject } : {}) };
}

function analyzeUrl(rawUrl, trustModel) {
  let candidate;
  try {
    candidate = canonicalUrl(rawUrl);
  } catch {
    return {
      input: rawUrl,
      classification: "invalid-url",
      indicators: [indicator("INVALID_URL", "high", "The URL could not be parsed.", rawUrl)],
    };
  }

  const indicators = [];
  const hostname = candidate.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const officialHosts = [...new Set(
    trustModel.roots.map((root) => new URL(root.url).hostname.toLowerCase()),
  )];
  const zone = matchingUntrustedZone(candidate, trustModel);
  const root = matchingRoot(candidate, trustModel);

  if (candidate.protocol !== "https:") {
    indicators.push(indicator("INSECURE_HTTP", "medium", "The URL does not use HTTPS.", rawUrl));
  }
  if (candidate.username || candidate.password) {
    indicators.push(indicator("URL_USERINFO", "high", "The URL hides a host behind user-info syntax.", rawUrl));
  }
  if (candidate.port && candidate.port !== "443") {
    indicators.push(indicator("NON_STANDARD_PORT", "medium", "The URL uses a non-standard port.", rawUrl));
  }
  if (isIpLiteral(hostname)) {
    indicators.push(indicator("IP_LITERAL_HOST", "medium", "The URL uses an IP address instead of a named official host.", rawUrl));
  }
  if (hostname.split(".").some((label) => label.startsWith("xn--"))) {
    indicators.push(indicator(
      "PUNYCODE_HOST",
      "medium",
      "The hostname uses Punycode and may visually imitate another domain.",
      rawUrl,
    ));
  }
  if (hasMixedConfusableScripts(hostname)) {
    indicators.push(indicator(
      "MIXED_SCRIPT_HOST",
      "high",
      "The hostname mixes scripts commonly used in visual impersonation.",
      rawUrl,
    ));
  }

  for (const officialHost of officialHosts) {
    const officialHostOrSubdomain = hostname === officialHost || hostname.endsWith(`.${officialHost}`);
    if (!officialHostOrSubdomain && hostname.includes(officialHost)) {
      indicators.push(indicator(
        "EMBEDDED_OFFICIAL_HOSTNAME",
        "high",
        `The hostname contains ${officialHost} but is controlled by another parent domain.`,
        rawUrl,
      ));
    } else if (!officialHostOrSubdomain && levenshtein(hostname, officialHost) <= 2) {
      indicators.push(indicator(
        "LOOKALIKE_OFFICIAL_HOSTNAME",
        "high",
        `The hostname is visually or textually close to ${officialHost}.`,
        rawUrl,
      ));
    }
  }

  if (zone) {
    indicators.push(indicator("USER_WRITABLE_OFFICIAL_SERVICE", "medium", zone.reason, rawUrl));
  }
  if (!root && !zone) {
    indicators.push(indicator(
      "UNVERIFIED_URL",
      "info",
      "The URL is not covered by the configured official trust roots.",
      rawUrl,
    ));
  }

  return {
    input: rawUrl,
    normalized: candidate.href,
    hostname,
    classification: zone ? "user-content-on-official-service" : root?.trust ?? "unverified",
    trustRootId: root?.id ?? null,
    indicators,
  };
}

function extractUrls(input) {
  return [...input.matchAll(URL_PATTERN)]
    .map((match) => match[0].replace(TRAILING_URL_PUNCTUATION, ""))
    .filter(Boolean);
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function verdictSummary(verdict) {
  return {
    HIGH_RISK_PATTERN: "One or more high-risk patterns require the user to stop and verify independently.",
    CONFLICTS_WITH_CURRENT_OFFICIAL_STATE: "The claim conflicts with the current monitored official state.",
    VERIFIED_OFFICIAL_ROOT: "The input points to an exact pinned official root and no risk pattern was detected.",
    OFFICIALLY_REFERENCED: "The input is inside a configured official namespace or referenced account.",
    UNVERIFIED: "The current evidence is insufficient to treat the input as official or safe.",
  }[verdict];
}

export async function analyzeClaimInBrowser(input, { trustModel, statusDocument }) {
  if (typeof input !== "string" || !input.trim()) {
    throw new Error("check input must contain visible text");
  }
  const normalizedInput = input.trim();
  const urls = extractUrls(normalizedInput).map((url) => analyzeUrl(url, trustModel));
  const addresses = [...new Set(normalizedInput.match(ADDRESS_PATTERN) ?? [])];
  const indicators = urls.flatMap((url) => url.indicators);
  const evidence = [];

  if (SECRET_REQUEST.test(normalizedInput)) {
    indicators.push(indicator(
      "SECRET_MATERIAL_REQUEST",
      "critical",
      "The text requests secret key material. Never disclose a private key, seed phrase, or recovery phrase.",
    ));
  }
  if (WALLET_CONNECT.test(normalizedInput)) {
    indicators.push(indicator(
      "WALLET_CONNECTION_REQUEST",
      "medium",
      "The text asks for a wallet connection; verify the exact origin and transaction before proceeding.",
    ));
  }

  const knownAddresses = new Set(
    (statusDocument.officialContracts ?? []).map((address) => address.toLowerCase()),
  );
  for (const address of addresses) {
    if (!knownAddresses.has(address.toLowerCase())) {
      indicators.push(indicator(
        "UNVERIFIED_CONTRACT_ADDRESS",
        "medium",
        "The address is not published as official in the current monitored dataset.",
        address,
      ));
    }
  }

  const tokenClaim = statusDocument.capabilities.find(
    (item) => item.id === "technocore-claim-token-endpoint",
  );
  const claimLanguage = CLAIM_LANGUAGE.test(normalizedInput);
  const technocoreClaimContext = /\btechnocore\b/i.test(normalizedInput) || urls.some(
    (url) => url.hostname === "technocore.chat",
  );
  if (claimLanguage && technocoreClaimContext && tokenClaim?.state === "not-offered-current-service") {
    indicators.push(indicator(
      "CLAIM_CONFLICTS_WITH_CURRENT_SERVICE",
      "high",
      "The text associates a claim, faucet, or airdrop with Technocore while its current specification says the service offers no claim/token endpoint.",
    ));
    evidence.push(...tokenClaim.evidence);
  }

  const hasHighRisk = indicators.some((item) => item.severity === "critical" || [
    "URL_USERINFO",
    "EMBEDDED_OFFICIAL_HOSTNAME",
    "LOOKALIKE_OFFICIAL_HOSTNAME",
    "MIXED_SCRIPT_HOST",
  ].includes(item.code));
  const hasConflict = indicators.some((item) => item.code === "CLAIM_CONFLICTS_WITH_CURRENT_SERVICE");
  const allExactRoots = urls.length > 0 && urls.every(
    (url) => url.classification === "official-root" && url.indicators.length === 0,
  );
  const allTrustedNamespaces = urls.length > 0 && urls.every(
    (url) => ["official-root", "official-namespace", "officially-referenced"].includes(url.classification) &&
      !url.indicators.some((item) => item.severity !== "info"),
  );

  let verdict = "UNVERIFIED";
  if (hasHighRisk) verdict = "HIGH_RISK_PATTERN";
  else if (hasConflict) verdict = "CONFLICTS_WITH_CURRENT_OFFICIAL_STATE";
  else if (allExactRoots && indicators.length === 0 && addresses.length === 0) {
    verdict = "VERIFIED_OFFICIAL_ROOT";
  } else if (allTrustedNamespaces && !indicators.some((item) => item.severity === "medium")) {
    verdict = "OFFICIALLY_REFERENCED";
  }

  return {
    schemaVersion: 1,
    datasetGeneratedAt: statusDocument.generatedAt,
    input: {
      sha256: await sha256(normalizedInput),
      length: [...normalizedInput].length,
      containsSecretRequestLanguage: SECRET_REQUEST.test(normalizedInput),
    },
    verdict,
    confidence: verdict === "UNVERIFIED" ? "low" : verdict === "OFFICIALLY_REFERENCED" ? "medium" : "high",
    summary: verdictSummary(verdict),
    indicators,
    urls,
    addresses,
    evidence,
    limitations: [
      "This is a deterministic evidence check, not a guarantee that a site or transaction is safe.",
      "The analyzer does not fetch user-submitted URLs and cannot inspect their current page content.",
      "Official sources may change after the dataset timestamp.",
    ],
  };
}
