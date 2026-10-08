import type {
  ApiKeyRecord,
  Audit,
  AuditList,
  CreatedApiKey,
  Member,
  Organization,
  Repository,
  Stats,
  BillingSummary,
  Invoice,
} from "@/lib/types";
import { fetchWithTimeout } from "@/lib/http";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function apiFetch<T>(path: string, init?: RequestInit, timeoutMs = 10000): Promise<T> {
  let response: Response;
  try {
    response = await fetchWithTimeout(
      `/api/dashboard/${path}`,
      {
        ...init,
        credentials: "same-origin",
        cache: "no-store",
        headers: { "Content-Type": "application/json", ...init?.headers },
      },
      timeoutMs,
    );
  } catch {
    throw new ApiError(
      504,
      "API unavailable or timed out. A sleeping free service can take about a minute to start; retry after it wakes.",
    );
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      message = (await response.json()).detail ?? message;
    } catch {
      /* Preserve status message. */
    }
    throw new ApiError(response.status, message);
  }
  return response.status === 204 ? (undefined as T) : (response.json() as Promise<T>);
}

export const getOrgs = (): Promise<Organization[]> => apiFetch("orgs");
export const getOrg = (orgId: string): Promise<Organization> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}`);
export const getStats = (orgId: string): Promise<Stats> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/stats`);
export const getRepos = (orgId: string): Promise<Repository[]> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/repos`);
export interface BranchPage {
  items: { name: string }[];
  next_page: number | null;
}
export const getRepoBranches = (orgId: string, repoId: string, page = 1): Promise<BranchPage> =>
  apiFetch(
    `orgs/${encodeURIComponent(orgId)}/repos/${encodeURIComponent(repoId)}/branches?page=${page}`,
    undefined,
    25000,
  );
export const startRepoAudit = (
  orgId: string,
  repoId: string,
  branch: string,
): Promise<{ audit_id: string; commit_sha: string; status: string }> =>
  apiFetch(
    `orgs/${encodeURIComponent(orgId)}/repos/${encodeURIComponent(repoId)}/audits`,
    { method: "POST", body: JSON.stringify({ branch }) },
    25000,
  );
export interface GithubRepository {
  full_name: string;
  private: boolean;
  default_branch: string;
}
export const discoverRepos = (
  orgId: string,
  page: number,
): Promise<{ items: GithubRepository[]; next_page: number | null }> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/github-repos?page=${page}`);
export const linkRepo = (orgId: string, fullName: string): Promise<Repository> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/repos`, {
    method: "POST",
    body: JSON.stringify({ github_repo_full_name: fullName }),
  });
export const getInstallation = (orgId: string): Promise<{ installation_id: number | null }> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/github-installation`);
export const connectInstallation = (
  orgId: string,
  installationId: number,
): Promise<{ installation_id: number }> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/github-installation`, {
    method: "POST",
    body: JSON.stringify({ installation_id: installationId }),
  });
export const getAudits = (
  orgId: string,
  options: { repoId?: string; timeRange?: "7d" | "30d" | "90d" } = {},
): Promise<AuditList> => {
  const query = new URLSearchParams({ limit: "200", time_range: options.timeRange ?? "7d" });
  if (options.repoId) query.set("repo_id", options.repoId);
  return apiFetch(`orgs/${encodeURIComponent(orgId)}/audits?${query}`);
};
export const getAudit = (auditId: string, orgId: string): Promise<Audit> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/audits/${encodeURIComponent(auditId)}`);
export const getMembers = (orgId: string): Promise<Member[]> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/members`);
export const getApiKeys = (orgId: string): Promise<ApiKeyRecord[]> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/keys`);
export const createApiKey = (orgId: string, name: string): Promise<CreatedApiKey> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/api-keys`, {
    method: "POST",
    body: JSON.stringify({ name }),
  });
export const revokeApiKey = (orgId: string, keyId: string): Promise<void> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/api-keys/${encodeURIComponent(keyId)}`, {
    method: "DELETE",
  });

export const getBilling = (orgId: string): Promise<BillingSummary> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/billing`);
export const getInvoices = (orgId: string): Promise<{ items: Invoice[] }> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/billing/invoices`);
export const createCheckout = (
  orgId: string,
  plan: "pro" | "team",
): Promise<{ url: string | null; development: boolean }> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/billing/checkout`, {
    method: "POST",
    body: JSON.stringify({ plan }),
  });
export const createPortal = (orgId: string): Promise<{ url: string }> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/billing/portal`, { method: "POST", body: "{}" });
export const activateDemoPlan = (
  orgId: string,
  plan: "pro" | "team",
): Promise<{ plan: "pro" | "team" }> =>
  apiFetch(`orgs/${encodeURIComponent(orgId)}/billing/dev-activate`, {
    method: "POST",
    body: JSON.stringify({ plan }),
  });

export async function getAuditDiff(auditId: string, orgId: string): Promise<string | null> {
  const response = await fetchWithTimeout(
    `/api/dashboard/orgs/${encodeURIComponent(orgId)}/audits/${encodeURIComponent(auditId)}/diff`,
    { cache: "no-store" },
  );
  if (response.status === 404) return null;
  if (!response.ok) throw new ApiError(response.status, "Could not load the linked GitHub diff");
  return response.text();
}
