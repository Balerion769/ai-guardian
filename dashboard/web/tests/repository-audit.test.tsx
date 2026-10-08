import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RepositoryAuditControl } from "@/components/repository-audit-control";
import { isAllowedProxyPath } from "@/lib/proxy";

const mocks = vi.hoisted(() => ({ branches: vi.fn(), start: vi.fn(), push: vi.fn() }));
vi.mock("@/lib/api", () => ({ getRepoBranches: mocks.branches, startRepoAudit: mocks.start }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: mocks.push }) }));
const repo = {
  id: "repo",
  github_repo_full_name: "owner/project",
  default_branch: "main",
  is_active: true,
  last_audit_at: null,
};
beforeEach(() => {
  mocks.branches.mockResolvedValue({
    items: [{ name: "main" }, { name: "feature/security" }],
    next_page: null,
  });
  mocks.start.mockResolvedValue({ audit_id: "saved-audit" });
});
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});

it("audits the selected branch and opens its saved audit", async () => {
  render(<RepositoryAuditControl orgId="org" repo={repo} />);
  await waitFor(() => expect(screen.getByRole("button", { name: "Audit now" })).toBeEnabled());
  fireEvent.change(screen.getByLabelText("Branch"), { target: { value: "feature/security" } });
  fireEvent.click(screen.getByRole("button", { name: "Audit now" }));
  await waitFor(() => expect(mocks.start).toHaveBeenCalledWith("org", "repo", "feature/security"));
  expect(mocks.push).toHaveBeenCalledWith("/dashboard/audits/saved-audit");
});

it("shows submission failures without claiming a successful audit", async () => {
  mocks.start.mockRejectedValue(new Error("Daily audit limit reached"));
  render(<RepositoryAuditControl orgId="org" repo={repo} />);
  await waitFor(() => expect(screen.getByRole("button", { name: "Audit now" })).toBeEnabled());
  fireEvent.click(screen.getByRole("button", { name: "Audit now" }));
  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent("Daily audit limit reached"),
  );
  expect(mocks.push).not.toHaveBeenCalled();
});

it("keeps offline demo and inactive repositories from submitting jobs", () => {
  render(<RepositoryAuditControl orgId="org" repo={{ ...repo, is_active: false }} />);
  expect(screen.getByRole("button", { name: "Audit now" })).toBeDisabled();
  expect(mocks.branches).not.toHaveBeenCalled();
});

it("allows only active-tenant branch reads and audit submissions through the proxy", () => {
  expect(isAllowedProxyPath(["orgs", "org", "repos", "repo", "branches"], "org", "GET")).toBe(true);
  expect(isAllowedProxyPath(["orgs", "org", "repos", "repo", "audits"], "org", "POST")).toBe(true);
  expect(isAllowedProxyPath(["orgs", "other", "repos", "repo", "audits"], "org", "POST")).toBe(
    false,
  );
  expect(isAllowedProxyPath(["orgs", "org", "repos", "repo", "branches"], "org", "POST")).toBe(
    false,
  );
});

it("loads additional branches without losing the selected branch", async () => {
  mocks.branches.mockResolvedValueOnce({ items: [{ name: "main" }], next_page: 2 });
  mocks.branches.mockResolvedValueOnce({ items: [{ name: "release/v2" }], next_page: null });
  render(<RepositoryAuditControl orgId="org" repo={repo} />);
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Load more branches" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Load more branches" }));
  await screen.findByRole("option", { name: "release/v2" });
  expect(screen.getByLabelText("Branch")).toHaveValue("main");
  expect(mocks.branches).toHaveBeenLastCalledWith("org", "repo", 2);
});

it("ignores stale branch responses after switching repositories", async () => {
  let resolveOld!: (value: unknown) => void;
  mocks.branches.mockReturnValueOnce(
    new Promise((resolve) => {
      resolveOld = resolve;
    }),
  );
  const view = render(<RepositoryAuditControl orgId="org" repo={repo} />);
  view.rerender(<RepositoryAuditControl orgId="org" repo={{ ...repo, id: "new-repo" }} />);
  await screen.findByRole("option", { name: "main" });
  resolveOld({ items: [{ name: "stale-branch" }], next_page: null });
  await waitFor(() => expect(screen.queryByRole("option", { name: "stale-branch" })).toBeNull());
});

it("does not submit duplicate jobs while the first request is pending", async () => {
  mocks.start.mockReturnValue(new Promise(() => {}));
  render(<RepositoryAuditControl orgId="org" repo={repo} />);
  const button = screen.getByRole("button", { name: "Audit now" });
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.click(button);
  fireEvent.click(button);
  expect(mocks.start).toHaveBeenCalledTimes(1);
  expect(button).toBeDisabled();
});
