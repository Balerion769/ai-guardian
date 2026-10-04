export type Severity = "HIGH" | "MEDIUM" | "LOW";
export type AuditStatus = "QUEUED" | "RUNNING" | "PASSED" | "FAILED" | "ERROR";

export interface Organization {
  id: string;
  name: string;
  github_slug: string | null;
  plan: "free" | "pro" | "team";
  daily_limit: number;
  billing_status?: "active" | "past_due";
  role: "owner" | "admin" | "member";
}

export interface Repository {
  id: string;
  github_repo_full_name: string;
  default_branch: string;
  is_active: boolean;
  last_audit_at: string | null;
}

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  description: string;
  remediation: string;
  file_path: string | null;
  line_number: number | null;
  line_reference: string;
  confidence: number;
  is_fixed: boolean;
  fixed_at: string | null;
}

export interface Audit {
  audit_id: string;
  org_id: string;
  repo_id: string | null;
  pr_number: number | null;
  commit_sha: string | null;
  branch: string | null;
  status: AuditStatus;
  risk_score: number;
  total_findings: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  diff_size: number;
  latency_ms: number;
  model_used: string | null;
  summary: string;
  created_at: string;
  findings: Finding[];
}

export interface AuditList {
  items: Audit[];
  total: number;
}
export interface DailyRisk {
  date: string;
  average_risk_score: number;
  audit_count: number;
}
export interface CategoryCount {
  category: string;
  count: number;
}
export interface VulnerableRepo {
  repo_id: string;
  github_repo_full_name: string;
  high_findings: number;
  audit_count: number;
}
export interface Stats {
  risk_over_time: DailyRisk[];
  findings_by_category: CategoryCount[];
  top_vulnerable_repos: VulnerableRepo[];
  mttr_hours: number | null;
}

export interface Member {
  user_id: string;
  role: "owner" | "admin" | "member";
  login?: string;
  email?: string | null;
  avatar_url?: string | null;
}
export interface ApiKeyRecord {
  id: string;
  name: string;
  prefix: string;
  last4: string;
  revoked: boolean;
}
export interface CreatedApiKey extends ApiKeyRecord {
  key: string;
}

export interface BillingSummary {
  plan: Organization["plan"];
  billing_status: "active" | "past_due";
  audits_today: number;
  daily_limit: number | null;
  seat_count: number;
  features: string[];
  has_subscription: boolean;
  has_customer: boolean;
}

export interface Invoice {
  id: string;
  number: string | null;
  status: string | null;
  amount_paid: number;
  currency: string;
  created: number | null;
  hosted_invoice_url: string | null;
}
