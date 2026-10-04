import type { AuditStatus } from "@/lib/types";
import { Badge } from "@/components/ui/badge";

export function StatusBadge({ status }: { status: AuditStatus }) {
  const tone: Record<AuditStatus, string> = {
    PASSED: "border-emerald-500/25 bg-emerald-500/10 text-emerald-300",
    FAILED: "border-red-500/25 bg-red-500/10 text-red-300",
    RUNNING: "border-blue-500/25 bg-blue-500/10 text-blue-300",
    QUEUED: "border-slate-500/25 bg-slate-500/10 text-slate-300",
    ERROR: "border-orange-500/25 bg-orange-500/10 text-orange-300",
  };
  return (
    <Badge className={tone[status]}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {status}
    </Badge>
  );
}
