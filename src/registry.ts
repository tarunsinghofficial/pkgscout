const REGISTRY = "https://registry.npmjs.org";

// Scoped names like @hono/node-server need the slash encoded in the URL path.
const encodeName = (name: string) => name.replace("/", "%2f");

// Cloudflare caches subrequests for us when we pass cacheTtl.
// Five minutes is plenty: package metadata doesn't change by the second.
async function getJson(url: string, init: RequestInit = {}) {
  const res = await fetch(url, {
    ...init,
    headers: { accept: "application/json", ...(init.headers ?? {}) },
    cf: init.method === "POST" ? undefined : { cacheTtl: 300, cacheEverything: true },
  } as RequestInit);
  return res;
}

type Neighbor = { name: string; latestVersion: string; description: string | null; warnings: string[] };

export type PackageReport =
  | { exists: false; name: string; similar: Neighbor[] }
  | {
      exists: true;
      name: string;
      latestVersion: string;
      description: string | null;
      license: string | null;
      deprecated: string | null;
      lastPublished: string | null;
      weeklyDownloads: number | null;
      maintainers: number;
      repository: string | null;
      warnings: string[];
    };

type Manifest = {
  version: string;
  description?: string;
  license?: string | { type?: string };
  deprecated?: string;
  repository?: string | { url?: string };
  maintainers?: unknown[];
};

// Plain-language flags the model can act on without guessing what the raw numbers mean.
function warningsFor(m: Manifest, weekly: number | null): string[] {
  const w: string[] = [];
  if (m.version.endsWith("-security")) {
    w.push("npm replaced this package with a security placeholder. The original was likely malicious. Do not install.");
  }
  if (m.deprecated) w.push(`Deprecated: ${m.deprecated}`);
  if (weekly !== null && weekly < 1000) w.push(`Only ${weekly} downloads last week.`);
  if (!m.repository) w.push("No source repository listed.");
  return w;
}

type SearchHit = {
  package: {
    name: string;
    date?: string;
    maintainers?: unknown[];
    links?: { repository?: string };
  };
  downloads?: { weekly?: number };
};

async function search(text: string, size = 10): Promise<SearchHit[]> {
  const res = await getJson(`${REGISTRY}/-/v1/search?text=${encodeURIComponent(text)}&size=${size}`);
  if (!res.ok) return [];
  const body = (await res.json()) as { objects?: SearchHit[] };
  return body.objects ?? [];
}

async function lookupNeighbor(name: string): Promise<Neighbor | null> {
  const res = await getJson(`${REGISTRY}/${encodeName(name)}/latest`);
  if (!res.ok) return null;
  const m = (await res.json()) as Manifest;
  const weekly = await weeklyDownloads(name).catch(() => null);
  return { name, latestVersion: m.version, description: m.description ?? null, warnings: warningsFor(m, weekly) };
}

// Search is the wrong tool for typos. "reqeusts" returns packages with a
// handful of weekly downloads that have nothing to do with "requests".
// Instead, try the mistakes people (and models) actually make: two letters
// swapped, or one letter dropped. Then keep only the names that exist.
function typoCandidates(name: string) {
  const out = new Set<string>();
  for (let i = 0; i < name.length - 1; i++) {
    out.add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2));
  }
  for (let i = 0; i < name.length; i++) {
    out.add(name.slice(0, i) + name.slice(i + 1));
  }
  out.delete(name);
  // Workers cap how many fetches one request can make (50 on the free plan),
  // so keep the fan-out bounded.
  return [...out].filter((n) => n.length > 1).slice(0, 20);
}

async function weeklyDownloads(name: string): Promise<number | null> {
  const res = await getJson(`https://api.npmjs.org/downloads/point/last-week/${name}`);
  if (!res.ok) return null;
  const body = (await res.json()) as { downloads?: number };
  return typeof body.downloads === "number" ? body.downloads : null;
}

export async function inspectPackage(name: string): Promise<PackageReport> {
  // /<name>/latest returns one small manifest. The full packument for a big
  // package like typescript is several megabytes, which is a bad idea on a
  // Worker with a tight CPU budget.
  const [latestRes, hits, downloads] = await Promise.all([
    getJson(`${REGISTRY}/${encodeName(name)}/latest`),
    search(name),
    weeklyDownloads(name).catch(() => null),
  ]);

  if (latestRes.status === 404) {
    const found = await Promise.all(typoCandidates(name).map(lookupNeighbor));
    return { exists: false, name, similar: found.filter((n): n is Neighbor => n !== null).slice(0, 5) };
  }
  if (!latestRes.ok) {
    throw new Error(`npm registry returned ${latestRes.status} for ${name}`);
  }

  const latest = (await latestRes.json()) as Manifest;

  // Search gives us download counts and the last publish date in one call.
  // It is fuzzy, so only trust the hit whose name matches exactly.
  const hit = hits.find((h) => h.package.name === name);

  const license = typeof latest.license === "string" ? latest.license : latest.license?.type ?? null;
  const repoField = typeof latest.repository === "string" ? latest.repository : latest.repository?.url;

  const weekly = downloads ?? hit?.downloads?.weekly ?? null;

  return {
    exists: true,
    name,
    latestVersion: latest.version,
    description: latest.description ?? null,
    license,
    deprecated: latest.deprecated ?? null,
    lastPublished: hit?.package.date ?? null,
    // Search quietly drops deprecated packages like `request`, so the
    // downloads API is the source of truth. Search is only a fallback.
    weeklyDownloads: weekly,
    maintainers: latest.maintainers?.length ?? hit?.package.maintainers?.length ?? 0,
    repository: hit?.package.links?.repository ?? repoField ?? null,
    warnings: warningsFor(latest, weekly),
  };
}

export type Advisory = {
  title: string;
  severity: string;
  vulnerableVersions: string;
  url: string;
};

// The same endpoint `npm audit` talks to. It wants exact versions, not ranges.
export async function checkVulnerabilities(
  packages: { name: string; version: string }[],
): Promise<Record<string, Advisory[]>> {
  const body: Record<string, string[]> = {};
  for (const { name, version } of packages) {
    (body[name] ??= []).push(version);
  }

  const res = await getJson(`${REGISTRY}/-/npm/v1/security/advisories/bulk`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`npm advisories endpoint returned ${res.status}`);

  const raw = (await res.json()) as Record<
    string,
    { title: string; severity: string; vulnerable_versions: string; url: string }[]
  >;

  const out: Record<string, Advisory[]> = {};
  for (const { name, version } of packages) {
    out[`${name}@${version}`] = (raw[name] ?? []).map((a) => ({
      title: a.title,
      severity: a.severity,
      vulnerableVersions: a.vulnerable_versions,
      url: a.url,
    }));
  }
  return out;
}
