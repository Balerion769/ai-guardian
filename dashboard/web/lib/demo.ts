import { randomBytes, randomUUID } from "node:crypto";
import type { ApiKeyRecord, Audit, Finding, Organization, Repository, Stats } from "@/lib/types";

const DAY = 86_400_000;
const ago = (days: number): string => new Date(Date.now() - days * DAY).toISOString();

export const demoOrg: Organization = {
  id: "demo-org",
  name: "Acme Engineering",
  github_slug: "acme",
  plan: "pro",
  daily_limit: 1000,
  billing_status: "active",
  role: "owner",
};

export const demoRepos: Repository[] = [
  {
    id: "repo-payments",
    github_repo_full_name: "acme/payments-api",
    default_branch: "main",
    is_active: true,
    last_audit_at: ago(0.13),
  },
  {
    id: "repo-platform",
    github_repo_full_name: "acme/platform-core",
    default_branch: "main",
    is_active: true,
    last_audit_at: ago(0.7),
  },
  {
    id: "repo-web",
    github_repo_full_name: "acme/web-console",
    default_branch: "main",
    is_active: true,
    last_audit_at: ago(1.2),
  },
  {
    id: "repo-auth",
    github_repo_full_name: "acme/auth-service",
    default_branch: "develop",
    is_active: true,
    last_audit_at: ago(2.1),
  },
];

const finding = (
  id: string,
  severity: Finding["severity"],
  category: string,
  file: string,
  line: number,
  description: string,
  remediation: string,
  confidence: number,
  isFixed = false,
): Finding => ({
  id,
  severity,
  category,
  file_path: file,
  line_number: line,
  line_reference: `${file}:Line ${line}`,
  description,
  remediation,
  confidence,
  is_fixed: isFixed,
  fixed_at: isFixed ? ago(0.5) : null,
});

const findings: Finding[] = [
  finding(
    "finding-1",
    "HIGH",
    "SQL Injection",
    "src/payments/query.py",
    84,
    "Untrusted account_id is interpolated into a SQL statement.",
    'cursor.execute("SELECT * FROM payments WHERE account_id = %s", (account_id,))',
    0.97,
  ),
  finding(
    "finding-2",
    "HIGH",
    "Secret Leak",
    "src/config/settings.py",
    18,
    "A production API credential is assigned as a literal.",
    'API_KEY = os.environ["PAYMENTS_API_KEY"]',
    0.99,
  ),
  finding(
    "finding-3",
    "MEDIUM",
    "Insecure Deserialization",
    "src/payments/cache.py",
    42,
    "A serialized payload is loaded without validation.",
    "payload = json.loads(cache_value)",
    0.86,
  ),
  finding(
    "finding-4",
    "LOW",
    "Debug Mode",
    "src/app.py",
    12,
    "Debug mode is enabled in the application entry point.",
    "app.run(debug=False)",
    0.93,
    true,
  ),
];

function audit(
  id: string,
  repoId: string,
  days: number,
  risk: number,
  items: Finding[],
  status: Audit["status"] = risk >= 40 ? "FAILED" : "PASSED",
): Audit {
  return {
    audit_id: id,
    org_id: demoOrg.id,
    repo_id: repoId,
    pr_number: id === "audit-1042" ? 142 : null,
    commit_sha: "a".repeat(40),
    branch: "feature/security-review",
    status,
    risk_score: risk,
    total_findings: items.length,
    high_count: items.filter((item) => item.severity === "HIGH").length,
    medium_count: items.filter((item) => item.severity === "MEDIUM").length,
    low_count: items.filter((item) => item.severity === "LOW").length,
    diff_size: 2514,
    latency_ms: 1328,
    model_used: "qwen2.5-coder",
    created_at: ago(days),
    findings: items,
    summary: items.length
      ? `Found ${items.length} security findings.`
      : "No security vulnerabilities detected in the supplied change.",
  };
}

export const demoAudits: Audit[] = [
  audit("audit-1042", "repo-payments", 0.13, 95, findings.slice(0, 3)),
  audit("audit-1041", "repo-platform", 0.7, 15, [findings[2]]),
  audit("audit-1040", "repo-web", 1.2, 0, []),
  audit("audit-1039", "repo-auth", 2.1, 5, [findings[3]]),
  audit("audit-1038", "repo-payments", 3.1, 40, [findings[0]]),
  audit("audit-1037", "repo-platform", 4.2, 0, []),
  audit("audit-1036", "repo-web", 5.3, 15, [findings[2]]),
  audit("audit-1035", "repo-auth", 6.2, 55, [findings[0], findings[2]]),
  audit("audit-1034", "repo-payments", 8.4, 65, findings.slice(0, 2)),
];

export function demoStats(): Stats {
  const grouped = new Map<string, number[]>();
  const categories = new Map<string, number>();
  const highs = new Map<string, { count: number; audits: number }>();
  for (const item of demoAudits) {
    const date = item.created_at.slice(0, 10);
    grouped.set(date, [...(grouped.get(date) ?? []), item.risk_score]);
    for (const row of item.findings)
      categories.set(row.category, (categories.get(row.category) ?? 0) + 1);
    if (item.repo_id) {
      const entry = highs.get(item.repo_id) ?? { count: 0, audits: 0 };
      entry.count += item.high_count;
      entry.audits += 1;
      highs.set(item.repo_id, entry);
    }
  }
  return {
    risk_over_time: [...grouped.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, values]) => ({
        date,
        average_risk_score: Math.round(values.reduce((a, b) => a + b, 0) / values.length),
        audit_count: values.length,
      })),
    findings_by_category: [...categories.entries()].map(([category, count]) => ({
      category,
      count,
    })),
    top_vulnerable_repos: demoRepos
      .filter((repo) => (highs.get(repo.id)?.count ?? 0) > 0)
      .map((repo) => ({
        repo_id: repo.id,
        github_repo_full_name: repo.github_repo_full_name,
        high_findings: highs.get(repo.id)!.count,
        audit_count: highs.get(repo.id)!.audits,
      }))
      .sort((a, b) => b.high_findings - a.high_findings),
    mttr_hours: 18.4,
  };
}

const demoKeys: ApiKeyRecord[] = [
  {
    id: "demo-key-1",
    name: "GitHub Actions",
    prefix: "ag_live_demo_ci_",
    last4: "9k2M",
    revoked: false,
  },
  {
    id: "demo-key-2",
    name: "Staging",
    prefix: "ag_live_demo_staging_",
    last4: "1pQ7",
    revoked: false,
  },
];

const json = (value: unknown, status = 200): Response =>
  Response.json(value, { status, headers: { "Cache-Control": "no-store" } });

/** Serve a synthetic, clearly labeled local experience without backend writes. */
export function demoResponse(
  path: string[],
  method: string,
  query: URLSearchParams,
  body: unknown,
): Response {
  const resource = path[2];
  if (resource === "billing") {
    if (path.length === 3 && method === "GET")
      return json({
        plan: demoOrg.plan,
        billing_status: "active",
        audits_today: 45,
        daily_limit: demoOrg.plan === "team" ? null : demoOrg.daily_limit,
        seat_count: 2,
        features:
          demoOrg.plan === "team"
            ? ["SSO (planned)", "SOC 2 export (planned)", "Custom rules (planned)"]
            : ["Autofix suggestions (planned)", "Slack webhook (planned)"],
        has_subscription: false,
        has_customer: false,
      });
    if (path[3] === "invoices" && method === "GET")
      return json({
        items: [
          {
            id: "in_demo",
            number: "DEMO-001",
            status: "paid",
            amount_paid: 3800,
            currency: "usd",
            created: Math.floor(Date.now() / 1000) - 86400 * 10,
            hosted_invoice_url: null,
          },
        ],
      });
    if (path[3] === "checkout" && method === "POST") return json({ url: null, development: true });
    if (path[3] === "dev-activate" && method === "POST") {
      const plan = typeof body === "object" && body !== null && "plan" in body ? body.plan : null;
      if (plan !== "pro" && plan !== "team") return json({ detail: "Invalid plan" }, 422);
      demoOrg.plan = plan;
      demoOrg.daily_limit = plan === "team" ? 2_147_483_647 : 1000;
      return json({ plan, development: true });
    }
    if (path[3] === "portal" && method === "POST")
      return json({ detail: "Demo has no Stripe customer" }, 409);
  }
  if (path.length === 1 && method === "GET") return json([demoOrg]);
  if (path.length === 2 && method === "GET") return json(demoOrg);
  if (resource === "repos" && path.length === 3) return json(demoRepos);
  if (resource === "stats" && path.length === 3) return json(demoStats());
  if (resource === "members" && path.length === 3)
    return json([
      { user_id: "demo-user", role: "owner" },
      { user_id: "demo-teammate", role: "member" },
    ]);
  if (resource === "audits") {
    if (path.length === 3) {
      const range = Number.parseInt(query.get("time_range") ?? "7d", 10);
      const items = demoAudits.filter(
        (item) =>
          Date.now() - new Date(item.created_at).getTime() <= range * DAY &&
          (!query.get("repo_id") || item.repo_id === query.get("repo_id")),
      );
      return json({ items, total: items.length });
    }
    const selected = demoAudits.find((item) => item.audit_id === path[3]);
    if (!selected) return json({ detail: "Audit not found" }, 404);
    if (path[4] === "diff")
      return new Response(
        'diff --git a/src/payments/query.py b/src/payments/query.py\n@@ -83,1 +84,1 @@\n+cursor.execute(f"SELECT * FROM payments WHERE account_id = {account_id}")\n',
        { headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" } },
      );
    return json(selected);
  }
  if (resource === "keys" && method === "GET") return json(demoKeys);
  if (resource === "api-keys" && method === "POST") {
    const name =
      typeof body === "object" && body !== null && "name" in body ? String(body.name).trim() : "";
    if (!name || name.length > 120) return json({ detail: "Enter a key name" }, 422);
    const id = randomUUID();
    const raw = `ag_live_${id}_${randomBytes(36).toString("base64url")}`;
    const record = { id, name, prefix: `ag_live_${id}_`, last4: raw.slice(-4), revoked: false };
    demoKeys.unshift(record);
    return json({ ...record, key: raw }, 201);
  }
  if (resource === "api-keys" && method === "DELETE") {
    const record = demoKeys.find((item) => item.id === path[3]);
    if (!record) return json({ detail: "API key not found" }, 404);
    record.revoked = true;
    return new Response(null, { status: 204 });
  }
  return json({ detail: "Demo operation unavailable" }, 404);
}
