import { describe, expect, it } from "vitest";
import { filterFindings } from "@/lib/findings";
import { demoEnabled, isAllowedMutationOrigin, isAllowedProxyPath } from "@/lib/proxy";
import type { Finding } from "@/lib/types";

const findings: Finding[] = [
  {
    id: "1",
    severity: "HIGH",
    category: "SQL Injection",
    file_path: "src/db.py",
    line_number: 12,
    line_reference: "src/db.py:Line 12",
    description: "unsafe SQL",
    remediation: "parameterize",
    confidence: 0.9,
    is_fixed: false,
    fixed_at: null,
  },
  {
    id: "2",
    severity: "LOW",
    category: "Debug Mode",
    file_path: "app.py",
    line_number: 4,
    line_reference: "app.py:Line 4",
    description: "debug",
    remediation: "disable",
    confidence: 1,
    is_fixed: true,
    fixed_at: "2026-10-04",
  },
];

describe("findings filters", () => {
  it("filters by severity, category, and file together", () => {
    expect(
      filterFindings(findings, { severity: "HIGH", category: "SQL Injection", file: "db.py" }).map(
        (item) => item.id,
      ),
    ).toEqual(["1"]);
    expect(
      filterFindings(findings, { severity: "LOW", category: "SQL Injection", file: "" }),
    ).toEqual([]);
  });
  it("shows all rows for empty filters", () => {
    expect(filterFindings(findings, { severity: "all", category: "all", file: "" })).toHaveLength(
      2,
    );
  });
});

describe("server proxy boundary", () => {
  it("allows GitHub discovery and binding only in the active organization", () => {
    expect(isAllowedProxyPath(["orgs", "mine", "github-repos"], "mine", "GET")).toBe(true);
    expect(isAllowedProxyPath(["orgs", "mine", "repos"], "mine", "POST")).toBe(true);
    expect(isAllowedProxyPath(["orgs", "mine", "github-installation"], "mine", "POST")).toBe(true);
    expect(isAllowedProxyPath(["orgs", "other", "github-installation"], "mine", "POST")).toBe(false);
    expect(isAllowedProxyPath(["orgs", "mine", "github-repos"], "mine", "POST")).toBe(false);
  });
  it("rejects another organization and unknown paths", () => {
    expect(isAllowedProxyPath(["orgs", "other", "stats"], "mine", "GET")).toBe(false);
    expect(isAllowedProxyPath(["orgs", "mine", "stats"], "mine", "GET")).toBe(true);
    expect(isAllowedProxyPath(["orgs", "mine", "secrets"], "mine", "GET")).toBe(false);
    expect(isAllowedProxyPath(["audit"], "mine", "POST")).toBe(false);
  });
  it("allows key creation and revocation only in the active organization", () => {
    expect(isAllowedProxyPath(["orgs", "mine", "api-keys"], "mine", "POST")).toBe(true);
    expect(isAllowedProxyPath(["orgs", "mine", "api-keys", "key"], "mine", "DELETE")).toBe(true);
    expect(isAllowedProxyPath(["orgs", "other", "api-keys"], "mine", "POST")).toBe(false);
  });
  it("allows only active-organization billing routes", () => {
    expect(isAllowedProxyPath(["orgs", "mine", "billing"], "mine", "GET")).toBe(true);
    expect(isAllowedProxyPath(["orgs", "mine", "billing", "checkout"], "mine", "POST")).toBe(true);
    expect(isAllowedProxyPath(["orgs", "mine", "billing", "portal"], "mine", "POST")).toBe(true);
    expect(isAllowedProxyPath(["orgs", "mine", "billing", "invoices"], "mine", "GET")).toBe(true);
    expect(isAllowedProxyPath(["orgs", "other", "billing"], "mine", "GET")).toBe(false);
    expect(isAllowedProxyPath(["orgs", "mine", "billing", "refund"], "mine", "POST")).toBe(false);
  });
  it("keeps demo mode out of production", () => {
    expect(demoEnabled("development", false)).toBe(true);
    expect(demoEnabled("production", false)).toBe(false);
  });
  it("rejects cross-origin mutations", () => {
    expect(isAllowedMutationOrigin("https://other.example", "https://guardian.example")).toBe(
      false,
    );
    expect(isAllowedMutationOrigin(null, "https://guardian.example")).toBe(false);
    expect(isAllowedMutationOrigin("https://guardian.example", "https://guardian.example")).toBe(
      true,
    );
  });
});
