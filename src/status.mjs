import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

export const DEFAULT_STATUS_PATH = "public/status.json";

function successfulSource(report, id) {
  const source = report.sources.find((candidate) => candidate.id === id);
  return source && source.status !== "error" ? source : null;
}

function evidenceFrom(source, observedAt) {
  if (!source) return [];
  return [{
    sourceId: source.id,
    url: source.url,
    finalUrl: source.finalUrl ?? source.url,
    observedAt,
    sha256: source.contentHash,
  }];
}

function capability({ id, label, state, detail, evidence = [] }) {
  return { id, label, state, detail, evidence };
}

export function buildStatusDocument(report) {
  if (report?.version !== 1 || !Array.isArray(report.sources)) {
    throw new Error("unsupported monitor report format");
  }

  const openapi = successfulSource(report, "technocore-openapi");
  const auth = successfulSource(report, "technocore-auth");
  const site = successfulSource(report, "flop-site");
  const github = successfulSource(report, "flop-github-repos");
  const openapiPaths = openapi?.summary?.paths ?? [];
  const noClaimOrToken = Boolean(auth?.summary?.explicitlySaysNoClaimOrTokenEndpoint);
  const noRegistration = Boolean(auth?.summary?.explicitlySaysNoRegistrationEndpoint);
  const observedAt = report.checkedAt;
  const monitoredEvidence = [
    ...evidenceFrom(openapi, observedAt),
    ...evidenceFrom(auth, observedAt),
    ...evidenceFrom(site, observedAt),
    ...evidenceFrom(github, observedAt),
  ];

  const capabilities = [
    capability({
      id: "technocore-service",
      label: "Technocore Chat / Notes",
      state: openapi ? "available" : "observation-error",
      detail: openapi
        ? `OpenAPI ${openapi.summary.specificationVersion}; service ${openapi.summary.infoVersion}`
        : "The current observation could not confirm the service.",
      evidence: evidenceFrom(openapi, observedAt),
    }),
    capability({
      id: "central-registration",
      label: "Central registration",
      state: noRegistration ? "not-offered-current-service" : "unconfirmed",
      detail: noRegistration
        ? "The current Technocore authentication document explicitly says there is nothing to register for."
        : "No conclusion can be drawn from the current dataset.",
      evidence: evidenceFrom(auth, observedAt),
    }),
    capability({
      id: "technocore-claim-token-endpoint",
      label: "Technocore claim / token endpoint",
      state: noClaimOrToken ? "not-offered-current-service" : "unconfirmed",
      detail: noClaimOrToken
        ? "The current Technocore authentication document explicitly says this service has no claim or token endpoint."
        : "No conclusion can be drawn from the current dataset.",
      evidence: evidenceFrom(auth, observedAt),
    }),
    capability({
      id: "faucet",
      label: "Official faucet",
      state: openapiPaths.some((item) => /faucet/i.test(item))
        ? "published-in-openapi"
        : "not-published-in-monitored-sources",
      detail: openapiPaths.some((item) => /faucet/i.test(item))
        ? "A faucet-related path is present in the monitored OpenAPI document."
        : "No faucet endpoint is present in the monitored OpenAPI document; this is not proof that no faucet exists elsewhere.",
      evidence: evidenceFrom(openapi, observedAt),
    }),
    capability({
      id: "testnet-rpc",
      label: "FLOP testnet RPC / chain ID",
      state: openapiPaths.some((item) => /rpc|chain/i.test(item))
        ? "published-in-openapi"
        : "not-published-in-monitored-sources",
      detail: "The monitored sources do not currently establish an RPC URL and chain ID.",
      evidence: monitoredEvidence,
    }),
    capability({
      id: "official-contracts",
      label: "Official FLOP contract addresses",
      state: "not-published-in-monitored-sources",
      detail: "No address is treated as official unless a pinned official source publishes it.",
      evidence: monitoredEvidence,
    }),
  ];

  return {
    schemaVersion: 1,
    project: {
      name: "FLOP Sentinel",
      status: "unofficial",
      purpose: "Evidence-based FLOP source and claim verification for people and agents.",
    },
    generatedAt: observedAt,
    sourceReportVersion: report.version,
    readOnlyObservations: true,
    disclaimer: [
      "This is an unofficial community dataset, not an endorsement by FLOP Labs.",
      "Unconfirmed does not mean fraudulent, and an official origin does not make user-written content trustworthy.",
      "This dataset does not establish airdrop eligibility or ownership of any token.",
    ],
    capabilities,
    officialContracts: [],
    sources: report.sources.map((source) => ({
      id: source.id,
      url: source.url,
      finalUrl: source.finalUrl ?? null,
      observedAt,
      status: source.status,
      sha256: source.contentHash ?? null,
      error: source.error ?? null,
    })),
  };
}

export async function readStatusDocument(filePath = DEFAULT_STATUS_PATH) {
  const parsed = JSON.parse(await readFile(path.resolve(filePath), "utf8"));
  if (parsed?.schemaVersion !== 1 || !Array.isArray(parsed.capabilities)) {
    throw new Error("unsupported status document format");
  }
  return parsed;
}

export async function writeStatusDocument(filePath, document) {
  const absolute = path.resolve(filePath);
  await mkdir(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}`;
  await writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, "utf8");
  await rename(temporary, absolute);
}

export function formatStatusDocument(document) {
  return [
    `FLOP Sentinel status (${document.generatedAt})`,
    ...document.capabilities.map(
      (item) => `- ${item.label}: ${item.state}\n  ${item.detail}`,
    ),
  ].join("\n");
}
