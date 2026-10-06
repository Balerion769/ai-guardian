import {afterEach, expect, it, vi} from "vitest";
import {cleanup, render, screen} from "@testing-library/react";
import GithubAppSettingsPage from "@/app/dashboard/settings/github/page";
vi.mock("@/components/github-connection", () => ({GithubConnection: () => <div>Connection</div>}));
afterEach(() => {cleanup(); vi.unstubAllEnvs();});
it("does not invent an installation URL when configuration is missing", () => {
  vi.stubEnv("GITHUB_APP_INSTALL_URL", "");
  vi.stubEnv("NEXT_PUBLIC_GITHUB_APP_INSTALL_URL", "");
  render(<GithubAppSettingsPage />);
  expect(screen.queryByRole("link", {name: /Install GitHub App/})).toBeNull();
});
it("uses the configured registered App URL", () => {
  const url = "https://github.com/apps/ai-guardian-balerion769/installations/new";
  vi.stubEnv("GITHUB_APP_INSTALL_URL", url);
  render(<GithubAppSettingsPage />);
  expect(screen.getByRole("link", {name: /Install GitHub App/})).toHaveAttribute("href", url);
});
