import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import AuditDetailPage from "@/app/dashboard/audits/[auditId]/page";
import type { Audit } from "@/lib/types";

const queued: Audit = {
  audit_id: "audit-1",
  org_id: "demo-org",
  repo_id: null,
  pr_number: null,
  commit_sha: null,
  branch: null,
  status: "QUEUED",
  risk_score: 0,
  total_findings: 0,
  high_count: 0,
  medium_count: 0,
  low_count: 0,
  diff_size: 12,
  latency_ms: 0,
  model_used: null,
  summary: "Queued",
  created_at: "2026-10-04T00:00:00Z",
  findings: [],
};
const getAuditMock = vi.fn(async (_auditId: string, _orgId: string) => queued);
vi.mock("next-auth/react", () => ({ useSession: () => ({ data: { orgId: "demo-org" } }) }));
vi.mock("@/lib/api", () => ({
  getAudit: (auditId: string, orgId: string) => getAuditMock(auditId, orgId),
  getRepos: vi.fn(async () => []),
  getAuditDiff: vi.fn(async () => null),
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  getAuditMock.mockClear();
});

describe("audit status", () => {
  it("refreshes a queued audit on a five-second interval", async () => {
    const interval = vi.spyOn(window, "setInterval");
    render(<AuditDetailPage params={Promise.resolve({ auditId: "audit-1" })} />);
    expect(await screen.findByText("Refreshing status every 5 seconds")).toBeInTheDocument();
    const polling = interval.mock.calls.find((call) => call[1] === 5_000);
    expect(polling).toBeDefined();
    await act(async () => {
      (polling![0] as () => void)();
    });
    expect(getAuditMock).toHaveBeenCalledTimes(2);
  });
});
