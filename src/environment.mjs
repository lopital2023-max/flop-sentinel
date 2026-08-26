import { access, readFile } from "node:fs/promises";
import path from "node:path";

export const REQUIRED_NODE_MAJOR = 22;
export const REQUIRED_NODE_MINOR = 12;

const REQUIRED_PROJECT_FILES = Object.freeze([
  "package.json",
  "config/sources.json",
  "config/trust-roots.json",
]);

export async function inspectEnvironment(projectRoot = process.cwd()) {
  const absoluteRoot = path.resolve(projectRoot);
  const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
  const supportedNode = Number.isInteger(nodeMajor) &&
    nodeMajor >= REQUIRED_NODE_MAJOR &&
    nodeMajor % 2 === 0 &&
    (nodeMajor > REQUIRED_NODE_MAJOR || nodeMinor >= REQUIRED_NODE_MINOR);
  const checks = [
    {
      id: "node-version",
      ok: supportedNode,
      actual: process.versions.node,
      expected: `an even-numbered release >=${REQUIRED_NODE_MAJOR}.${REQUIRED_NODE_MINOR}`,
    },
  ];

  for (const relativePath of REQUIRED_PROJECT_FILES) {
    try {
      await access(path.join(absoluteRoot, relativePath));
      checks.push({ id: `file:${relativePath}`, ok: true });
    } catch {
      checks.push({ id: `file:${relativePath}`, ok: false });
    }
  }

  try {
    const packageDocument = JSON.parse(
      await readFile(path.join(absoluteRoot, "package.json"), "utf8"),
    );
    const hasRuntimeDependencies = Object.keys(packageDocument.dependencies ?? {}).length > 0;
    checks.push({
      id: "dependency-free-runtime",
      ok: !hasRuntimeDependencies,
      actual: hasRuntimeDependencies ? "runtime dependencies present" : "none",
    });
    checks.push({
      id: "astro-build-tool",
      ok: typeof packageDocument.devDependencies?.astro === "string",
      actual: packageDocument.devDependencies?.astro ?? "missing",
    });
  } catch (error) {
    checks.push({
      id: "package-json-readable",
      ok: false,
      actual: error instanceof Error ? error.message : String(error),
    });
  }

  return {
    version: 1,
    projectRoot: absoluteRoot,
    platform: process.platform,
    architecture: process.arch,
    node: process.versions.node,
    packageManager: "npm",
    runtimeDependenciesRequired: false,
    ok: checks.every((check) => check.ok),
    checks,
  };
}

export function formatEnvironmentReport(report) {
  return [
    `FLOP Sentinel environment: ${report.ok ? "ready" : "not ready"}`,
    `Node.js ${report.node} (${report.platform}/${report.architecture})`,
    ...report.checks.map(
      (check) => `- ${check.ok ? "OK" : "FAIL"} ${check.id}${check.actual ? `: ${check.actual}` : ""}`,
    ),
  ].join("\n");
}
