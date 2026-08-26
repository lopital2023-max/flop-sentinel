import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

export const DEFAULT_PUBLICATION_PATHS = Object.freeze({
  report: ".local/last-report.json",
  changes: "public/changes.json",
  trustRoots: "config/trust-roots.json",
  sources: "public/sources.json",
  feed: "public/feed.xml",
});

export const DEFAULT_PUBLIC_SITE_URL = "https://lopital2023-max.github.io/flop-sentinel/";

function validateSiteUrl(value) {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error("public site URL must be a clean HTTPS URL");
  }
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return url.href;
}

function validateReport(report) {
  if (
    report?.version !== 1 ||
    !Array.isArray(report.sources) ||
    typeof report.checkedAt !== "string"
  ) {
    throw new Error("unsupported monitor report for public source data");
  }
  if (report.sources.some((source) => source.status === "error")) {
    throw new Error("public source data refused because the latest observation contains an error");
  }
}

function validateTrustRoots(trustRoots) {
  if (
    trustRoots?.version !== 1 ||
    !Array.isArray(trustRoots.roots) ||
    !Array.isArray(trustRoots.untrustedHostedZones)
  ) {
    throw new Error("unsupported trust-root data");
  }
}

export function buildSourcesDocument(report, trustRoots) {
  validateReport(report);
  validateTrustRoots(trustRoots);
  return {
    schemaVersion: 1,
    type: "flop-sentinel-source-register",
    generatedAt: report.checkedAt,
    collectionPolicy: {
      networkMode: "read-only",
      allowlistOnly: true,
      maximumResponseBytes: 5 * 1024 * 1024,
      redirectLimit: 3,
      redirectHostsPinned: true,
      userSubmittedUrlFetch: false,
    },
    monitoredSources: report.sources.map((source) => ({
      id: source.id,
      kind: source.kind,
      url: source.url,
      finalUrl: source.finalUrl,
      observedAt: report.checkedAt,
      httpStatus: source.httpStatus,
      contentType: source.contentType,
      observationStatus: source.status,
      normalizedSha256: source.contentHash,
      raw: {
        sha256: source.rawContentHash,
        bytes: source.rawByteLength,
        path: source.snapshotPath,
      },
    })),
    trustRoots: trustRoots.roots,
    untrustedHostedZones: trustRoots.untrustedHostedZones,
    disclaimer: [
      "This is an unofficial community-maintained source register.",
      "A pinned origin is evidence of provenance, not a guarantee of safety or truth.",
      "Technocore room and note paths remain user-writable content.",
    ],
  };
}

function escapeXml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

export function buildAtomFeed(changes, { siteUrl = DEFAULT_PUBLIC_SITE_URL } = {}) {
  if (changes?.schemaVersion !== 1 || !Array.isArray(changes.events)) {
    throw new Error("unsupported changes data for Atom feed");
  }
  const canonicalSiteUrl = validateSiteUrl(siteUrl);
  const updated = changes.generatedAt ?? "1970-01-01T00:00:00.000Z";
  const entries = changes.events.map((event) => {
    const summary = event.summary.join(" ");
    return [
      "  <entry>",
      `    <id>${escapeXml(`${canonicalSiteUrl}changes/#${encodeURIComponent(event.id)}`)}</id>`,
      `    <title>${escapeXml(`${event.sourceId}: ${event.kind}`)}</title>`,
      `    <updated>${escapeXml(event.observedAt)}</updated>`,
      `    <link rel="alternate" href="${escapeXml(event.sourceUrl)}" />`,
      `    <summary>${escapeXml(summary)}</summary>`,
      `    <category term="${escapeXml(event.severity)}" />`,
      "  </entry>",
    ].join("\n");
  });
  return [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<feed xmlns="http://www.w3.org/2005/Atom">',
    "  <id>urn:flop-sentinel:source-changes</id>",
    "  <title>FLOP Sentinel source changes</title>",
    `  <updated>${escapeXml(updated)}</updated>`,
    `  <link rel="self" href="${escapeXml(`${canonicalSiteUrl}feed.xml`)}" />`,
    `  <link rel="alternate" href="${escapeXml(`${canonicalSiteUrl}changes/`)}" />`,
    "  <subtitle>Unofficial official-source change signals; review primary evidence before acting.</subtitle>",
    ...entries,
    "</feed>",
    "",
  ].join("\n");
}

async function writeAtomic(filePath, contents) {
  const absolute = path.resolve(filePath);
  await mkdir(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}`;
  await writeFile(temporary, contents, "utf8");
  await rename(temporary, absolute);
}

export async function writePublicationData({
  reportPath = DEFAULT_PUBLICATION_PATHS.report,
  changesPath = DEFAULT_PUBLICATION_PATHS.changes,
  trustRootsPath = DEFAULT_PUBLICATION_PATHS.trustRoots,
  sourcesPath = DEFAULT_PUBLICATION_PATHS.sources,
  feedPath = DEFAULT_PUBLICATION_PATHS.feed,
  siteUrl = DEFAULT_PUBLIC_SITE_URL,
} = {}) {
  const [report, changes, trustRoots] = await Promise.all([
    readFile(path.resolve(reportPath), "utf8").then(JSON.parse),
    readFile(path.resolve(changesPath), "utf8").then(JSON.parse),
    readFile(path.resolve(trustRootsPath), "utf8").then(JSON.parse),
  ]);
  const sources = buildSourcesDocument(report, trustRoots);
  const feed = buildAtomFeed(changes, { siteUrl });
  await Promise.all([
    writeAtomic(sourcesPath, `${JSON.stringify(sources, null, 2)}\n`),
    writeAtomic(feedPath, feed),
  ]);
  return { sources, feed };
}
