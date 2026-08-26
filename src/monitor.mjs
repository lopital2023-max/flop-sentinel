import { createHash } from "node:crypto";
import {
  appendFile,
  mkdir,
  open,
  readFile,
  rename,
  writeFile,
} from "node:fs/promises";
import path from "node:path";

const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const SOURCE_KINDS = new Set(["openapi", "text", "html", "github-repos"]);
const OFFICIAL_SOURCE_URLS = new Set([
  "https://technocore.chat/openapi.json",
  "https://technocore.chat/auth.md",
  "https://flop.finance/",
  "https://api.github.com/orgs/flop-labs/repos?per_page=100&type=public",
]);
const REDIRECT_HOSTS = new Set([
  "technocore.chat",
  "flop.finance",
  "www.flop.finance",
  "api.github.com",
]);
const INTERESTING = /faucet|claim|token|wallet|rpc|inference|compute|testnet/i;

export const DEFAULT_MONITOR_PATHS = Object.freeze({
  config: "config/sources.json",
  state: ".local/monitor-state.json",
  report: ".local/last-report.json",
  history: ".local/monitor-history.jsonl",
  snapshots: "public/evidence/snapshots",
});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export async function loadSources(configPath = DEFAULT_MONITOR_PATHS.config) {
  const parsed = JSON.parse(await readFile(path.resolve(configPath), "utf8"));
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error("monitor source config must be a non-empty array");
  }
  const seenIds = new Set();
  return parsed.map((source) => {
    if (!/^[a-z0-9][a-z0-9-]{0,47}$/.test(source.id ?? "")) {
      throw new Error(`invalid source id: ${JSON.stringify(source.id)}`);
    }
    if (seenIds.has(source.id)) throw new Error(`duplicate source id: ${source.id}`);
    seenIds.add(source.id);
    if (!SOURCE_KINDS.has(source.kind)) {
      throw new Error(`unsupported source kind for ${source.id}: ${source.kind}`);
    }
    if (!OFFICIAL_SOURCE_URLS.has(source.url)) {
      throw new Error(`source URL is not on the pinned official allowlist: ${source.url}`);
    }
    return { id: source.id, url: source.url, kind: source.kind };
  });
}

async function readResponseLimited(response) {
  const declaredLength = Number(response.headers.get("content-length") ?? 0);
  if (declaredLength > MAX_RESPONSE_BYTES) {
    throw new Error(`response exceeds ${MAX_RESPONSE_BYTES} bytes`);
  }
  if (!response.body) return Buffer.alloc(0);

  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error(`response exceeds ${MAX_RESPONSE_BYTES} bytes`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

export async function fetchOfficialSource(
  source,
  { fetchImpl = globalThis.fetch, timeoutMilliseconds = 15_000 } = {},
) {
  if (!OFFICIAL_SOURCE_URLS.has(source.url)) {
    throw new Error(`refusing unpinned source URL: ${source.url}`);
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMilliseconds);
  let current = new URL(source.url);

  try {
    for (let redirectCount = 0; redirectCount <= 3; redirectCount += 1) {
      if (current.protocol !== "https:" || !REDIRECT_HOSTS.has(current.hostname)) {
        throw new Error(`redirect left the official host allowlist: ${current.href}`);
      }
      const response = await fetchImpl(current, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          accept: "application/json, text/plain, text/html;q=0.9",
          "user-agent": "flop-local-monitor/0.1 (+local read-only monitor)",
        },
      });

      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("location");
        if (!location) throw new Error(`redirect from ${current.href} had no Location`);
        current = new URL(location, current);
        continue;
      }
      if (!response.ok) {
        const body = (await readResponseLimited(response)).toString("utf8");
        throw new Error(`HTTP ${response.status}: ${body.slice(0, 300)}`);
      }
      const rawBody = await readResponseLimited(response);
      let body;
      try {
        body = new TextDecoder("utf-8", { fatal: true }).decode(rawBody);
      } catch {
        throw new Error(`official source ${current.href} was not valid UTF-8`);
      }
      return {
        body,
        rawBody,
        finalUrl: current.href,
        status: response.status,
        contentType: response.headers.get("content-type") ?? "application/octet-stream",
      };
    }
    throw new Error("too many redirects");
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeText(text) {
  return text
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, ""))
    .join("\n")
    .trim();
}

function htmlToText(html) {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function keywordLines(text) {
  const pieces = text.split(/\n+|(?<=[.!?])\s+/u);
  return [...new Set(pieces.filter((line) => INTERESTING.test(line)).map((line) => line.trim()))]
    .filter(Boolean)
    .slice(0, 30);
}

export function normalizeSource(kind, body) {
  if (kind === "openapi") {
    const document = JSON.parse(body);
    if (typeof document.openapi !== "string" || typeof document.paths !== "object") {
      throw new Error("unexpected Technocore OpenAPI document");
    }
    const paths = Object.keys(document.paths).sort();
    const normalized = stableStringify(document);
    return {
      normalized,
      summary: {
        specificationVersion: document.openapi,
        infoVersion: String(document.info?.version ?? "unknown"),
        paths,
        interestingPaths: paths.filter((item) => INTERESTING.test(item)),
      },
    };
  }

  if (kind === "github-repos") {
    const repositories = JSON.parse(body);
    if (!Array.isArray(repositories)) throw new Error("unexpected GitHub repository list");
    const selected = repositories
      .map((repo) => ({
        name: String(repo.name),
        htmlUrl: String(repo.html_url),
        description: repo.description == null ? null : String(repo.description),
        pushedAt: repo.pushed_at == null ? null : String(repo.pushed_at),
        defaultBranch: repo.default_branch == null ? null : String(repo.default_branch),
        archived: Boolean(repo.archived),
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
    return {
      normalized: stableStringify(selected),
      summary: {
        repositories: selected,
        interestingRepositories: selected
          .filter((repo) => INTERESTING.test(`${repo.name} ${repo.description ?? ""}`))
          .map((repo) => repo.name),
      },
    };
  }

  const normalized = kind === "html" ? htmlToText(body) : normalizeText(body);
  return {
    normalized,
    summary: {
      keywordLines: keywordLines(normalized),
      explicitlySaysNoRegistrationEndpoint:
        /there is no authentication, and nothing to register for/i.test(normalized) ||
        /there (?:is|are) no registration(?:, provisioning)?(?: or|,) claim/i.test(normalized) ||
        /no `register_uri`, because there is nothing to register/i.test(normalized),
      explicitlySaysNoClaimOrTokenEndpoint:
        /no (?:registration,? )?(?:provisioning,? )?claim or token endpoint/i.test(normalized) ||
        /there is nothing to claim/i.test(normalized),
    },
  };
}

function setDifference(after, before) {
  const oldValues = new Set(before);
  return after.filter((value) => !oldValues.has(value));
}

export function compareSummaries(kind, before, after) {
  if (kind === "openapi") {
    const addedPaths = setDifference(after.paths, before.paths);
    const removedPaths = setDifference(before.paths, after.paths);
    return {
      specificationVersion: before.specificationVersion === after.specificationVersion
        ? null
        : { before: before.specificationVersion, after: after.specificationVersion },
      infoVersion: before.infoVersion === after.infoVersion
        ? null
        : { before: before.infoVersion, after: after.infoVersion },
      addedPaths,
      removedPaths,
      alerts: addedPaths.filter((item) => INTERESTING.test(item)).map(
        (item) => `new interesting OpenAPI path: ${item}`,
      ),
    };
  }

  if (kind === "github-repos") {
    const oldNames = before.repositories.map((repo) => repo.name);
    const newNames = after.repositories.map((repo) => repo.name);
    const addedRepositories = setDifference(newNames, oldNames);
    const removedRepositories = setDifference(oldNames, newNames);
    const changedRepositories = after.repositories
      .filter((repo) => {
        const old = before.repositories.find((candidate) => candidate.name === repo.name);
        return old && stableStringify(old) !== stableStringify(repo);
      })
      .map((repo) => repo.name);
    return {
      addedRepositories,
      removedRepositories,
      changedRepositories,
      alerts: addedRepositories
        .filter((name) => after.interestingRepositories.includes(name))
        .map((name) => `new potentially relevant repository: ${name}`),
    };
  }

  const addedKeywordLines = setDifference(after.keywordLines, before.keywordLines);
  const removedKeywordLines = setDifference(before.keywordLines, after.keywordLines);
  const alerts = [];
  if (
    before.explicitlySaysNoClaimOrTokenEndpoint &&
    !after.explicitlySaysNoClaimOrTokenEndpoint
  ) {
    alerts.push("the explicit 'no claim/token endpoint' statement disappeared; review manually");
  }
  return { addedKeywordLines, removedKeywordLines, alerts };
}

async function readState(statePath) {
  try {
    const parsed = JSON.parse(await readFile(path.resolve(statePath), "utf8"));
    if (parsed.version !== 1 || typeof parsed.sources !== "object") {
      throw new Error("unsupported monitor-state format");
    }
    return parsed;
  } catch (error) {
    if (error.code === "ENOENT") return { version: 1, sources: {} };
    throw error;
  }
}

async function writeJsonAtomic(filePath, value) {
  const absolute = path.resolve(filePath);
  await mkdir(path.dirname(absolute), { recursive: true, mode: 0o700 });
  const temporary = `${absolute}.tmp-${process.pid}`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await rename(temporary, absolute);
}

async function persistSnapshot(snapshotDirectory, rawBody, expectedHash) {
  const absoluteDirectory = path.resolve(snapshotDirectory);
  await mkdir(absoluteDirectory, { recursive: true, mode: 0o755 });
  const filePath = path.join(absoluteDirectory, `${expectedHash}.snapshot`);
  try {
    const handle = await open(filePath, "wx", 0o644);
    try {
      await handle.writeFile(rawBody);
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const existing = await readFile(filePath);
    if (!existing.equals(rawBody) || sha256(existing) !== expectedHash) {
      throw new Error(`snapshot collision or corruption for ${expectedHash}`);
    }
  }
  return `evidence/snapshots/${expectedHash}.snapshot`;
}

export async function runMonitor({
  configPath = DEFAULT_MONITOR_PATHS.config,
  statePath = DEFAULT_MONITOR_PATHS.state,
  reportPath = DEFAULT_MONITOR_PATHS.report,
  historyPath = DEFAULT_MONITOR_PATHS.history,
  snapshotDirectory = null,
  noWrite = false,
  fetchImpl = globalThis.fetch,
} = {}) {
  const sources = await loadSources(configPath);
  const previousState = await readState(statePath);
  const checkedAt = new Date().toISOString();

  const results = await Promise.all(
    sources.map(async (source) => {
      try {
        const fetched = await fetchOfficialSource(source, { fetchImpl });
        const processed = normalizeSource(source.kind, fetched.body);
        const contentHash = sha256(processed.normalized);
        const rawContentHash = sha256(fetched.rawBody);
        const snapshotPath = snapshotDirectory && !noWrite
          ? await persistSnapshot(snapshotDirectory, fetched.rawBody, rawContentHash)
          : null;
        const previous = previousState.sources[source.id];
        const status = !previous
          ? "baseline"
          : previous.contentHash === contentHash
            ? "unchanged"
            : "changed";
        return {
          id: source.id,
          url: source.url,
          finalUrl: fetched.finalUrl,
          kind: source.kind,
          httpStatus: fetched.status,
          contentType: fetched.contentType,
          status,
          contentHash,
          rawContentHash,
          rawByteLength: fetched.rawBody.byteLength,
          snapshotPath,
          summary: processed.summary,
          diff: status === "changed"
            ? compareSummaries(source.kind, previous.summary, processed.summary)
            : null,
        };
      } catch (error) {
        return {
          id: source.id,
          url: source.url,
          kind: source.kind,
          status: "error",
          error: error instanceof Error ? error.message : String(error),
        };
      }
    }),
  );

  const alerts = results.flatMap((result) =>
    (result.diff?.alerts ?? []).map((message) => ({ source: result.id, message })),
  );
  const report = {
    version: 1,
    checkedAt,
    readOnlyRemoteOperations: true,
    counts: {
      baseline: results.filter((item) => item.status === "baseline").length,
      unchanged: results.filter((item) => item.status === "unchanged").length,
      changed: results.filter((item) => item.status === "changed").length,
      error: results.filter((item) => item.status === "error").length,
      alerts: alerts.length,
    },
    alerts,
    sources: results,
  };

  if (!noWrite) {
    const nextSources = { ...previousState.sources };
    for (const result of results) {
      if (result.status === "error") continue;
      nextSources[result.id] = {
        url: result.url,
        finalUrl: result.finalUrl,
        kind: result.kind,
        contentHash: result.contentHash,
        rawContentHash: result.rawContentHash,
        rawByteLength: result.rawByteLength,
        snapshotPath: result.snapshotPath,
        contentType: result.contentType,
        summary: result.summary,
        checkedAt,
      };
    }
    await writeJsonAtomic(statePath, { version: 1, sources: nextSources });
    await writeJsonAtomic(reportPath, report);
    const absoluteHistory = path.resolve(historyPath);
    await mkdir(path.dirname(absoluteHistory), { recursive: true, mode: 0o700 });
    await appendFile(absoluteHistory, `${JSON.stringify(report)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
  }
  return report;
}

export function formatMonitorReport(report) {
  const lines = [
    `FLOP official-source check: ${report.checkedAt}`,
    `baseline=${report.counts.baseline} unchanged=${report.counts.unchanged} changed=${report.counts.changed} errors=${report.counts.error} alerts=${report.counts.alerts}`,
  ];
  for (const source of report.sources) {
    lines.push(`- ${source.id}: ${source.status}${source.error ? ` (${source.error})` : ""}`);
    if (source.summary?.infoVersion) {
      lines.push(`  OpenAPI: ${source.summary.specificationVersion}; service version: ${source.summary.infoVersion}`);
    }
    if (source.summary?.repositories) {
      lines.push(`  repositories: ${source.summary.repositories.map((repo) => repo.name).join(", ") || "none"}`);
    }
    for (const alert of source.diff?.alerts ?? []) lines.push(`  ALERT: ${alert}`);
  }
  return lines.join("\n");
}
