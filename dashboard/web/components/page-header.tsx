export function PageHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="mb-7 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
      <div>
        <div className="mono mb-2 text-[10px] font-medium uppercase tracking-[.2em] text-emerald-300">
          {eyebrow}
        </div>
        <h1 className="text-2xl font-semibold tracking-[-.04em] text-white sm:text-[30px]">
          {title}
        </h1>
        <p className="mt-2 text-sm text-slate-500">{description}</p>
      </div>
      {action}
    </div>
  );
}
