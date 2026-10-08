import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { LoginActions } from "@/components/login-actions";
const mocks = vi.hoisted(() => ({ signIn: vi.fn() }));
vi.mock("next-auth/react", () => ({ signIn: mocks.signIn }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); mocks.signIn.mockReset(); });
describe("GitHub login readiness", () => {
  it("waits for a healthy backend before beginning GitHub OAuth", async () => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    render(<LoginActions demo={false} />);
    fireEvent.click(screen.getByRole("button", { name: /Sign in with GitHub/ }));
    await waitFor(() => expect(mocks.signIn).toHaveBeenCalledWith("github", { callbackUrl: "/dashboard" }));
    expect(fetchMock).toHaveBeenCalledWith("/api/auth/backend-ready", expect.objectContaining({ cache: "no-store" }));
  });
  it("shows an availability error and does not start OAuth when the backend is asleep", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response('{}', { status: 503 })));
    render(<LoginActions demo={false} />);
    fireEvent.click(screen.getByRole("button", { name: /Sign in with GitHub/ }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toMatch(/starting|unavailable/i));
    expect(mocks.signIn).not.toHaveBeenCalled();
  });
});
