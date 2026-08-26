import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { domainToUnicode } from "node:url";

export const DEFAULT_TRUST_ROOTS_PATH = "config/trust-roots.json";

const ROOT_SCOPES = new Set(["exact-url", "path-prefix"]);
const ROOT_TRUST_LEVELS = new Set([
  "official-root",
  "official-namespace",
  "officially-referenced",
]);
const SECRET_REQUEST = /(?:private[\s_-]*key|seed[\s_-]*phrase|recovery[\s_-]*phrase|mnemonic|秘密鍵|シード(?:フレーズ)?|復元フレーズ|ニーモニック)/iu;
const CLAIM_LANGUAGE = /(?:\bclaim\b|\bfaucet\b|\bairdrop\b|エアドロップ|エアドロ|トークン.{0,20}(?:受け取|受取|請求)|無料.{0,12}トークン)/iu;
const WALLET_CONNECT = /(?:connect[\s_-]*(?:your[\s_-]*)?wallet|wallet[\s_-]*connect|ウォレット.{0,10}(?:接続|連携))/iu;
const ADDRESS_PATTERN = /\b0x[a-fA-F0-9]{40}\b/g;
const URL_PATTERN = /https?:\/\/[^\s<>"'`）)\]}]+/giu;
const TRAILING_URL_PUNCTUATION = /[.,;:!?。、「」』】]+$/u;

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function canonicalUrl(url) {
  const candidate = new URL(url);
  candidate.hash = "";
  return candidate;
}

function validateTrustModel(parsed) {
  if (parsed?.version !== 1 || !Array.isArray(parsed.roots)) {
    throw new Error("unsupported trust-root config format");
  }
  const rootIds = new Set();
  const roots = parsed.roots.map((root) => {
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(root.id ?? "")) {
      throw new Error(`invalid trust-root id: ${JSON.stringify(root.id)}`);
    }
    if (rootIds.has(root.id)) throw new Error(`duplicate trust-root id: ${root.id}`);
    rootIds.add(root.id);
    if (!ROOT_SCOPES.has(root.scope)) throw new Error(`invalid scope for ${root.id}`);
    if (!ROOT_TRUST_LEVELS.has(root.trust)) throw new Error(`invalid trust for ${root.id}`);
    const url = canonicalUrl(root.url);
    if (url.protocol !== "https:") throw new Error(`trust root must use HTTPS: ${root.id}`);
    return { ...root, url: url.href };
  });

  const untrustedHostedZones = (parsed.untrustedHostedZones ?? []).map((zone) => {
    const origin = new URL(zone.origin);
    if (origin.protocol !== "https:" || origin.origin !== zone.origin) {
      throw new Error(`invalid untrusted hosted-zone origin: ${zone.id}`);
    }
    if (!zone.pathPrefix?.startsWith("/")) {
      throw new Error(`invalid untrusted hosted-zone path: ${zone.id}`);
    }
    return { ...zone, origin: origin.origin };
  });

  return { version: 1, roots, untrustedHostedZones };
}

export async function loadTrustModel(configPath = DEFAULT_TRUST_ROOTS_PATH) {
  return validateTrustModel(
    JSON.parse(await readFile(path.resolve(configPath), "utf8")),
  );
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
  return trustModel.untrustedHostedZones.find(
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

function hasMixedConfusableScripts(hostname) {
  const unicode = domainToUnicode(hostname);
  const hasLatin = /\p{Script=Latin}/u.test(unicode);
  const hasCyrillic = /\p{Script=Cyrillic}/u.test(unicode);
  const hasGreek = /\p{Script=Greek}/u.test(unicode);
  return hasLatin && (hasCyrillic || hasGreek);
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
  if (isIP(hostname)) {
    indicators.push(indicator("IP_LITERAL_HOST", "medium", "The URL uses an IP address instead of a named official host.", rawUrl));
  }
  if (hostname.split(".").some((label) => label.startsWith("xn--"))) {
    indicators.push(indicator("PUNYCODE_HOST", "medium", "The hostname contains an internationalized Punycode label.", rawUrl));
  }
  if (hasMixedConfusableScripts(hostname)) {
    indicators.push(indicator("MIXED_SCRIPT_HOST", "high", "The hostname mixes scripts commonly used in visual impersonation.", rawUrl));
  }

  for (const officialHost of officialHosts) {
    const isOfficialHostOrSubdomain = hostname === officialHost || hostname.endsWith(`.${officialHost}`);
    if (!isOfficialHostOrSubdomain && hostname.includes(officialHost)) {
      indicators.push(indicator(
        "EMBEDDED_OFFICIAL_HOSTNAME",
        "high",
        `The hostname contains ${officialHost} but is controlled by another parent domain.`,
        rawUrl,
      ));
    } else if (!isOfficialHostOrSubdomain && levenshtein(hostname, officialHost) <= 2) {
      indicators.push(indicator(
        "LOOKALIKE_OFFICIAL_HOSTNAME",
        "high",
        `The hostname is visually or textually close to ${officialHost}.`,
        rawUrl,
      ));
    }
  }

  if (zone) {
    indicators.push(indicator(
      "USER_WRITABLE_OFFICIAL_SERVICE",
      "medium",
      zone.reason,
      rawUrl,
    ));
  }
  if (!root && !zone) {
    indicators.push(indicator(
      "UNVERIFIED_URL",
      "info",
      "The URL is not covered by the configured official trust roots.",
      rawUrl,
    ));
  }

  const classification = zone
    ? "user-content-on-official-service"
    : root?.trust ?? "unverified";
  return {
    input: rawUrl,
    normalized: candidate.href,
    hostname,
    classification,
    trustRootId: root?.id ?? null,
    indicators,
  };
}

function extractUrls(input) {
  return [...input.matchAll(URL_PATTERN)]
    .map((match) => match[0].replace(TRAILING_URL_PUNCTUATION, ""))
    .filter(Boolean);
}

function findCapability(statusDocument, id) {
  return statusDocument?.capabilities?.find((item) => item.id === id) ?? null;
}

function verdictSummary(verdict) {
  const summaries = {
    HIGH_RISK_PATTERN: "One or more high-risk patterns require the user to stop and verify independently.",
    CONFLICTS_WITH_CURRENT_OFFICIAL_STATE: "The claim conflicts with the current monitored official state.",
    VERIFIED_OFFICIAL_ROOT: "The input points to an exact pinned official root and no risk pattern was detected.",
    OFFICIALLY_REFERENCED: "The input is inside a configured official namespace or referenced account.",
    UNVERIFIED: "The current evidence is insufficient to treat the input as official or safe.",
  };
  return summaries[verdict];
}

export function analyzeClaim(input, { trustModel, statusDocument }) {
  if (typeof input !== "string" || !input.trim()) {
    throw new Error("check input must contain visible text");
  }
  if (!trustModel) throw new Error("a trust model is required");
  if (!statusDocument) throw new Error("a status document is required");

  const normalizedInput = input.trim();
  const urls = extractUrls(normalizedInput).map((url) => analyzeUrl(url, trustModel));
  const addresses = [...new Set(normalizedInput.match(ADDRESS_PATTERN) ?? [])];
  const indicators = urls.flatMap((url) => url.indicators);
  const evidence = [];
  const claimLanguage = CLAIM_LANGUAGE.test(normalizedInput);

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
  if (addresses.length > 0) {
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
  }

  const tokenClaim = findCapability(statusDocument, "technocore-claim-token-endpoint");
  const technocoreClaimContext = /\btechnocore\b/i.test(normalizedInput) || urls.some(
    (url) => url.hostname === "technocore.chat",
  );
  if (
    claimLanguage &&
    technocoreClaimContext &&
    tokenClaim?.state === "not-offered-current-service"
  ) {
    indicators.push(indicator(
      "CLAIM_CONFLICTS_WITH_CURRENT_SERVICE",
      "high",
      "The text associates a claim, faucet, or airdrop with Technocore while its current specification says the service offers no claim/token endpoint.",
    ));
    evidence.push(...tokenClaim.evidence);
  }

  const hasCriticalOrHighRisk = indicators.some(
    (item) => item.severity === "critical" || [
      "URL_USERINFO",
      "EMBEDDED_OFFICIAL_HOSTNAME",
      "LOOKALIKE_OFFICIAL_HOSTNAME",
      "MIXED_SCRIPT_HOST",
    ].includes(item.code),
  );
  const hasCurrentStateConflict = indicators.some(
    (item) => item.code === "CLAIM_CONFLICTS_WITH_CURRENT_SERVICE",
  );
  const allExactRoots = urls.length > 0 && urls.every(
    (url) => url.classification === "official-root" && url.indicators.length === 0,
  );
  const allTrustedNamespaces = urls.length > 0 && urls.every(
    (url) => ["official-root", "official-namespace", "officially-referenced"].includes(url.classification) &&
      !url.indicators.some((item) => item.severity !== "info"),
  );

  let verdict = "UNVERIFIED";
  if (hasCriticalOrHighRisk) verdict = "HIGH_RISK_PATTERN";
  else if (hasCurrentStateConflict) verdict = "CONFLICTS_WITH_CURRENT_OFFICIAL_STATE";
  else if (allExactRoots && indicators.length === 0 && addresses.length === 0) {
    verdict = "VERIFIED_OFFICIAL_ROOT";
  } else if (allTrustedNamespaces && !indicators.some((item) => item.severity === "medium")) {
    verdict = "OFFICIALLY_REFERENCED";
  }

  const confidence = verdict === "UNVERIFIED"
    ? "low"
    : verdict === "OFFICIALLY_REFERENCED"
      ? "medium"
      : "high";

  return {
    schemaVersion: 1,
    datasetGeneratedAt: statusDocument.generatedAt,
    input: {
      sha256: sha256(normalizedInput),
      length: [...normalizedInput].length,
      containsSecretRequestLanguage: SECRET_REQUEST.test(normalizedInput),
    },
    verdict,
    confidence,
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

export function formatClaimAnalysis(result) {
  const lines = [
    `Verdict: ${result.verdict} (${result.confidence})`,
    result.summary,
    `Dataset: ${result.datasetGeneratedAt}`,
  ];
  for (const item of result.indicators) {
    lines.push(`- [${item.severity}] ${item.code}: ${item.message}`);
  }
  if (result.indicators.length === 0) lines.push("- No configured risk indicator was triggered.");
  return lines.join("\n");
}
