import * as React from "react";
import { cn } from "@/lib/utils";

export function Table({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="thin-scroll w-full overflow-x-auto">
      <table className={cn("w-full border-collapse text-left text-sm", className)} {...props} />
    </div>
  );
}
export function TableHeader(props: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <thead {...props} />;
}
export function TableBody(props: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody {...props} />;
}
export function TableRow({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr
      className={cn(
        "border-b border-white/[.06] transition-colors hover:bg-white/[.025]",
        className,
      )}
      {...props}
    />
  );
}
export function TableHead({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      className={cn(
        "px-5 py-3 text-[10px] font-semibold uppercase tracking-[.14em] text-slate-500",
        className,
      )}
      {...props}
    />
  );
}
export function TableCell({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn("px-5 py-4 align-middle", className)} {...props} />;
}
