import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FindingsTable } from "@/components/findings-table";
import { ApiKeyCreateModal } from "@/components/api-key-create-modal";
import type { Finding } from "@/lib/types";

vi.mock("@/lib/api", () => ({
  createApiKey: vi.fn(async () => ({
    id: "key-1",
    name: "CI",
    prefix: "ag_live_",
    last4: "a123",
    key: "ag_live_secret-a123",
    revoked: false,
  })),
}));
afterEach(cleanup);

const rows: Finding[] = [
  {
    id: "sql",
    severity: "HIGH",
    category: "SQL Injection",
    description: "Unsafe query",
    remediation: "Use placeholders",
    file_path: "db.py",
    line_number: 10,
    line_reference: "db.py:Line 10",
    confidence: 0.9,
    is_fixed: false,
    fixed_at: null,
  },
  {
    id: "debug",
    severity: "LOW",
    category: "Debug Mode",
    description: "Debug enabled",
    remediation: "Disable debug",
    file_path: "main.py",
    line_number: 2,
    line_reference: "main.py:Line 2",
    confidence: 1,
    is_fixed: true,
    fixed_at: "2026-10-04",
  },
];

describe("dashboard interactions", () => {
  it("filters findings by severity and opens remediation", async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={rows} />);
    await user.selectOptions(screen.getByLabelText("Severity"), "HIGH");
    expect(within(screen.getByRole("table")).getByText("SQL Injection")).toBeInTheDocument();
    expect(within(screen.getByRole("table")).queryByText("Debug Mode")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /view fix/i }));
    expect(screen.getByText("Use placeholders")).toBeInTheDocument();
  });

  it("shows a new API key once and clears it when closed", async () => {
    const user = userEvent.setup();
    render(<ApiKeyCreateModal orgId="demo-org" onCreated={() => undefined} />);
    await user.click(screen.getByRole("button", { name: /create api key/i }));
    await user.type(screen.getByLabelText("Key name"), "CI");
    await user.click(screen.getByRole("button", { name: /^create key$/i }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("ag_live_secret-a123")).toBeInTheDocument();
    expect(within(dialog).getByText(/copy now, you won't see it again/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close dialog" }));
    await user.click(screen.getByRole("button", { name: /create api key/i }));
    expect(screen.queryByText("ag_live_secret-a123")).not.toBeInTheDocument();
  });
});
