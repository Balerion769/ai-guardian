import { afterEach, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { DiffViewer } from "@/components/diff-viewer";

afterEach(cleanup);

it("paginates large patches and keeps every line accessible", () => {
  render(<DiffViewer diff={Array.from({ length: 1001 }, (_, i) => `+line-${i + 1}`).join("\n")} />);
  expect(screen.getByText("Lines 1–500 of 1001")).toBeInTheDocument();
  expect(screen.queryByText("+line-501")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Next diff page" }));
  expect(screen.getByText("+line-501")).toBeInTheDocument();
  expect(screen.queryByText("+line-1")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Next diff page" }));
  expect(screen.getByText("+line-1001")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Next diff page" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Previous diff page" }));
  expect(screen.getByText("+line-501")).toBeInTheDocument();
});

it("resets pagination when the diff changes", () => {
  const view = render(<DiffViewer diff={"+first\n".repeat(501)} />);
  fireEvent.click(screen.getByRole("button", { name: "Next diff page" }));
  view.rerender(<DiffViewer diff="+replacement" />);
  expect(screen.getByText("+replacement")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Previous diff page" })).toBeDisabled();
});
