import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

export const DEFAULT_CHANGES_PATH = "public/changes.json";

function summarizeDiff(source) {
  const diff = source.diff ?? {};
  const details = [];
  if (diff.infoVersion) {
    details.push(`Service version changed from ${diff.infoVersion.before} to ${diff.infoVersion.after}.`);
  }
  if (diff.specificationVersion) {
    details.push(`OpenAPI version changed from ${diff.specificationVersion.before} to ${diff.specificationVersion.after}.`);
  }
  if (diff.addedPaths?.length) details.push(`Added paths: ${diff.addedPaths.join(", ")}.`);
  if (diff.removedPaths?.length) details.push(`Removed paths: ${diff.removedPaths.join(", ")}.`);
  if (diff.addedRepositories?.length) {
    details.push(`Added repositories: ${diff.addedRepositories.join(", ")}.`);
  }
  if (diff.removedRepositories?.length) {
    details.push(`Removed repositories: ${diff.removedRepositories.join(", ")}.`);
  }
  if (diff.changedRepositories?.length) {
    details.push(`Updated repositories: ${diff.changedRepositories.join(", ")}.`);
  }
  if (diff.addedKeywordLines?.length || diff.removedKeywordLines?.length) {
    details.push("Relevant wording changed; review the source directly.");
  }
  return details.length > 0 ? details : ["The normalized content hash changed."];
}

export function buildChangesDocument(reports, { limit = 100 } = {}) {
  if (!Array.isArray(reports)) throw new TypeError("reports must be an array");
  const validReports = reports.filter(
    (report) => report?.version === 1 && typeof report.checkedAt === "string" && Array.isArray(report.sources),
  );
  const events = [];

  for (const report of validReports) {
    for (const source of report.sources) {
      if (source.status !== "changed") continue;
      events.push({
        id: `${report.checkedAt}:${source.id}`,
        observedAt: report.checkedAt,
        sourceId: source.id,
        sourceUrl: source.url,
        kind: "source-change",
        severity: source.diff?.alerts?.length ? "review" : "notice",
        summary: summarizeDiff(source),
        sha256: source.contentHash ?? null,
      });
    }
    for (const alert of report.alerts ?? []) {
      events.push({
        id: `${report.checkedAt}:${alert.source}:alert:${events.length}`,
        observedAt: report.checkedAt,
        sourceId: alert.source,
        sourceUrl: report.sources.find((source) => source.id === alert.source)?.url ?? null,
        kind: "monitor-alert",
        severity: "review",
        summary: [String(alert.message)],
        sha256: report.sources.find((source) => source.id === alert.source)?.contentHash ?? null,
      });
    }
  }

  events.sort((left, right) => right.observedAt.localeCompare(left.observedAt));
  const latest = validReports.toSorted(
    (left, right) => right.checkedAt.localeCompare(left.checkedAt),
  )[0];
  return {
    schemaVersion: 1,
    generatedAt: latest?.checkedAt ?? null,
    observationCount: validReports.length,
    eventCount: events.length,
    events: events.slice(0, limit),
    disclaimer: "A source change is not automatically a product or protocol change. Review its evidence URL.",
  };
}

export async function readMonitorHistory(historyPath) {
  let contents;
  try {
    contents = await readFile(path.resolve(historyPath), "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  return contents
    .split("\n")
    .filter((line) => line.trim())
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error(`invalid monitor history JSON on line ${index + 1}`);
      }
    });
}

export async function readChangesDocument(filePath = DEFAULT_CHANGES_PATH) {
  const parsed = JSON.parse(await readFile(path.resolve(filePath), "utf8"));
  if (parsed?.schemaVersion !== 1 || !Array.isArray(parsed.events)) {
    throw new Error("unsupported changes document format");
  }
  return parsed;
}

export async function writeChangesDocument(filePath, document) {
  const absolute = path.resolve(filePath);
  await mkdir(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}`;
  await writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, "utf8");
  await rename(temporary, absolute);
}

export function formatChangesDocument(document) {
  const lines = [
    `FLOP Sentinel changes (${document.generatedAt ?? "no observations"})`,
    `observations=${document.observationCount} events=${document.eventCount}`,
  ];
  for (const event of document.events) {
    lines.push(`- ${event.observedAt} ${event.sourceId}: ${event.summary.join(" ")}`);
  }
  if (document.events.length === 0) lines.push("- No source changes recorded.");
  return lines.join("\n");
}
