import { LoaderCircle, TriangleAlert } from "lucide-react";

export function LoadingState({ label = "Loading security data..." }: { label?: string }) {
  return (
    <div className="flex min-h-72 items-center justify-center gap-3 text-sm text-slate-500">
      <LoaderCircle className="animate-spin text-emerald-300" size={18} />
      {label}
    </div>
  );
}
export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="surface flex min-h-52 flex-col items-center justify-center rounded-xl p-8 text-center">
      <TriangleAlert className="text-amber-300" size={24} />
      <h2 className="mt-4 text-sm font-semibold">Could not load this view</h2>
      <p className="mt-1 max-w-lg text-xs leading-6 text-slate-500">{message}</p>
      {retry && (
        <button
          onClick={retry}
          className="mt-4 text-xs font-semibold text-emerald-300 hover:underline"
        >
          Try again
        </button>
      )}
    </div>
  );
}
