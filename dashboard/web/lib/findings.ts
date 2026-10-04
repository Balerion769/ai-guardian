import type { Finding } from "@/lib/types";

export interface FindingFilters {
  severity: string;
  category: string;
  file: string;
}

export function filterFindings(findings: Finding[], filters: FindingFilters): Finding[] {
  const file = filters.file.trim().toLowerCase();
  return findings.filter(
    (finding) =>
      (filters.severity === "all" || finding.severity === filters.severity) &&
      (filters.category === "all" || finding.category === filters.category) &&
      (!file || (finding.file_path ?? finding.line_reference).toLowerCase().includes(file)),
  );
}
