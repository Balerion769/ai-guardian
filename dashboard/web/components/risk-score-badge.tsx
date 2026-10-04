import { Badge } from "@/components/ui/badge";

export function RiskScoreBadge({
  score,
  showLabel = true,
}: {
  score: number;
  showLabel?: boolean;
}) {
  const clamped = Math.min(100, Math.max(0, score));
  const tone =
    clamped < 30
      ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
      : clamped < 70
        ? "border-amber-500/25 bg-amber-500/10 text-amber-300"
        : "border-red-500/25 bg-red-500/10 text-red-300";
  const label = clamped < 30 ? "Low risk" : clamped < 70 ? "Elevated" : "Critical";
  return (
    <Badge className={tone}>
      <span className="mono text-xs font-bold">{clamped}</span>
      {showLabel && <span>{label}</span>}
    </Badge>
  );
}
