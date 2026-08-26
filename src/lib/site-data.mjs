import { readFile } from "node:fs/promises";
import path from "node:path";

async function readJson(relativePath) {
  return JSON.parse(await readFile(path.join(process.cwd(), relativePath), "utf8"));
}

export async function loadSiteData() {
  const [status, changes, trust] = await Promise.all([
    readJson("public/status.json"),
    readJson("public/changes.json"),
    readJson("config/trust-roots.json"),
  ]);
  if (status.schemaVersion !== 1 || changes.schemaVersion !== 1 || trust.version !== 1) {
    throw new Error("website data schema mismatch");
  }
  return { status, changes, trust };
}
