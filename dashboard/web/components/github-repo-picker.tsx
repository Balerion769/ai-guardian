"use client";

import {useEffect, useState} from "react";
import {useSession} from "next-auth/react";
import {discoverRepos, linkRepo, type GithubRepository} from "@/lib/api";
import {Button} from "@/components/ui/button";

/** Paginated GitHub discovery; linking still enforces server-side plan limits. */
export function GithubRepoPicker({linked, onLinked}: {linked: string[]; onLinked: () => void}) {
  const {data: session} = useSession();
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<GithubRepository[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  useEffect(() => {
    if (!open || !session?.orgId) return;
    let active = true;
    setBusy(true); setError(""); setItems([]);
    discoverRepos(session.orgId, page).then(result => {if (active) {setItems(result.items); setNext(result.next_page);}})
      .catch(caught => {if (active) setError(caught instanceof Error ? caught.message : "GitHub unavailable");})
      .finally(() => {if (active) setBusy(false);});
    return () => {active = false;};
  }, [open, session?.orgId, page]);
  async function link(name: string) {
    if (!session?.orgId) return;
    setBusy(true); setError("");
    try {await linkRepo(session.orgId, name); onLinked();}
    catch (caught) {setError(caught instanceof Error ? caught.message : "Link failed");}
    finally {setBusy(false);}
  }
  return <section className="mb-5 rounded-lg border border-white/10 p-4">
    <Button onClick={() => setOpen(!open)}>{open ? "Close repository picker" : "Link GitHub repository"}</Button>
    {open && <div className="mt-4 space-y-3">
      <p className="text-xs text-slate-400">Repositories you can manage on GitHub. Free supports 3 linked repositories. Install and connect the GitHub App for automatic PR audits.</p>
      <input aria-label="Search available GitHub repositories" placeholder="Search this page" value={search} onChange={event => setSearch(event.target.value)} className="rounded border border-white/10 bg-slate-900 p-2 text-sm" />
      {error && <p role="alert" className="text-red-300">{error}</p>}
      {busy && <p>Loading...</p>}
      {items.filter(item => item.full_name.toLowerCase().includes(search.toLowerCase())).map(item =>
        <div key={item.full_name} className="flex items-center justify-between gap-3 text-sm">
          <span>{item.full_name} {item.private ? "(private)" : "(public)"}</span>
          <Button disabled={busy || linked.includes(item.full_name)} onClick={() => link(item.full_name)}>{linked.includes(item.full_name) ? "Linked" : "Link"}</Button>
        </div>)}
      <div className="flex gap-3"><Button disabled={busy || page === 1} onClick={() => setPage(page - 1)}>Previous</Button><span>Page {page}</span><Button disabled={busy || next === null} onClick={() => setPage(next!)}>Next</Button></div>
    </div>}
  </section>;
}
