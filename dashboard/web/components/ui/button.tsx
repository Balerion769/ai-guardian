import * as React from "react";
import { cn } from "@/lib/utils";

type Variant = "default" | "outline" | "ghost" | "danger";
const variants: Record<Variant, string> = {
  default:
    "bg-emerald-400 text-[#072016] hover:bg-emerald-300 border-emerald-300/40 shadow-[0_0_20px_rgba(52,211,153,.12)]",
  outline: "bg-white/[.04] text-slate-100 hover:bg-white/[.08] border-white/15",
  ghost: "bg-transparent text-slate-300 hover:bg-white/[.06] border-transparent",
  danger: "bg-red-500/10 text-red-300 hover:bg-red-500/20 border-red-500/25",
};

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: "default" | "sm" | "icon";
}
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "default", size = "default", ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg border font-semibold transition-colors disabled:pointer-events-none disabled:opacity-50",
        size === "sm" ? "h-8 px-3 text-xs" : size === "icon" ? "h-9 w-9" : "h-10 px-4 text-sm",
        variants[variant],
        className,
      )}
      {...props}
    />
  );
});
