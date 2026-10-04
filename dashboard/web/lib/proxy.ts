const IDENTIFIER = /^[A-Za-z0-9_-]{1,80}$/;

export function demoEnabled(environment: string, hasGithubCredentials: boolean): boolean {
  return environment !== "production" && !hasGithubCredentials;
}

export function isAllowedMutationOrigin(origin: string | null, requestOrigin: string): boolean {
  return origin === requestOrigin;
}

/** Restrict the server proxy to the active tenant and dashboard operations. */
export function isAllowedProxyPath(path: string[], orgId: string, method: string): boolean {
  if (path.some((part) => !IDENTIFIER.test(part))) return false;
  if (path.length === 1 && path[0] === "orgs") return method === "GET" || method === "POST";
  if (path[0] !== "orgs" || path[1] !== orgId) return false;
  if (path.length === 2) return method === "GET";
  const resource = path[2];
  if (path.length === 3) {
    if (["repos", "audits", "stats", "members", "keys"].includes(resource)) return method === "GET";
    if (resource === "api-keys") return method === "POST";
    if (resource === "billing") return method === "GET";
  }
  if (resource === "billing" && path.length === 4) {
    if (path[3] === "invoices") return method === "GET";
    if (["checkout", "portal", "dev-activate"].includes(path[3])) return method === "POST";
  }
  if (resource === "audits" && path.length === 4) return method === "GET";
  if (resource === "audits" && path.length === 5 && path[4] === "diff") return method === "GET";
  if (resource === "api-keys" && path.length === 4) return method === "DELETE";
  return false;
}
