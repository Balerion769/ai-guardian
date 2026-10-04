import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import BillingPanel from "@/app/dashboard/settings/billing";

let plan: "free" | "pro" | "team" = "free";
const activate = vi.fn(async (_org: string, selected: "pro" | "team") => {
  plan = selected;
  return { plan: selected };
});
vi.mock("next-auth/react", () => ({
  useSession: () => ({ data: { orgId: "demo-org", demo: true } }),
}));
vi.mock("@/lib/api", () => ({
  getBilling: vi.fn(async () => ({
    plan,
    billing_status: "active",
    audits_today: 45,
    daily_limit: plan === "team" ? null : plan === "pro" ? 1000 : 100,
    seat_count: 1,
    features: [],
    has_subscription: false,
    has_customer: false,
  })),
  getOrg: vi.fn(async () => ({
    id: "demo-org",
    name: "Demo",
    plan,
    role: "owner",
    daily_limit: 100,
  })),
  getInvoices: vi.fn(async () => ({ items: [] })),
  createCheckout: vi.fn(async () => ({ url: null, development: true })),
  activateDemoPlan: (...args: [string, "pro" | "team"]) => activate(...args),
  createPortal: vi.fn(),
}));
afterEach(() => {
  cleanup();
  plan = "free";
  activate.mockClear();
});

describe("billing page", () => {
  it("shows quota usage and locally activates Pro only after explicit upgrade", async () => {
    const user = userEvent.setup();
    render(<BillingPanel />);
    expect(await screen.findByText("45 / 100")).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "45");
    await user.click(screen.getByRole("button", { name: "Upgrade to Pro" }));
    expect(activate).toHaveBeenCalledWith("demo-org", "pro");
    expect(await screen.findByText("45 / 1,000")).toBeInTheDocument();
  });
});
