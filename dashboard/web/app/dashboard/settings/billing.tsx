"use client";

import { useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { ArrowUpRight, CreditCard, ShieldCheck } from "lucide-react";
import {
  activateDemoPlan,
  createCheckout,
  createPortal,
  getBilling,
  getInvoices,
  getOrg,
} from "@/lib/api";
import type { BillingSummary, Invoice, Organization } from "@/lib/types";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ErrorState, LoadingState } from "@/components/load-state";

const tiers = [
  {
    plan: "free",
    price: 0,
    quota: "100 audits/day",
    features: ["1 organization", "3 repositories", "Community support"],
  },
  {
    plan: "pro",
    price: 19,
    quota: "1,000 audits/day",
    features: [
      "Unlimited repositories",
      "7-day audit retention",
      "Autofix suggestions (planned)",
      "Slack webhook (planned)",
    ],
  },
  {
    plan: "team",
    price: 49,
    quota: "Unlimited audits",
    features: [
      "90-day audit retention",
      "SSO (planned)",
      "SOC 2 export (planned)",
      "Custom rules (planned)",
    ],
  },
] as const;

function stripeDestination(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === "https:" &&
      ["checkout.stripe.com", "billing.stripe.com", "invoice.stripe.com"].includes(parsed.hostname)
    );
  } catch {
    return false;
  }
}

export default function BillingPanel() {
  const { data: session } = useSession();
  const orgId = session?.orgId;
  const [billing, setBilling] = useState<BillingSummary | null>(null);
  const [org, setOrg] = useState<Organization | null>(null);
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [error, setError] = useState("");
  const [invoiceError, setInvoiceError] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    if (!orgId) return;
    const [summary, organization] = await Promise.all([getBilling(orgId), getOrg(orgId)]);
    setBilling(summary);
    setOrg(organization);
    if (organization.role === "owner") {
      try {
        setInvoices((await getInvoices(orgId)).items);
        setInvoiceError("");
      } catch (caught) {
        setInvoiceError(caught instanceof Error ? caught.message : "Invoices unavailable");
      }
    }
  }, [orgId]);

  useEffect(() => {
    refresh().catch((caught) =>
      setError(caught instanceof Error ? caught.message : "Billing unavailable"),
    );
  }, [refresh]);

  async function upgrade(plan: "pro" | "team") {
    if (!orgId) return;
    setBusy(true);
    setError("");
    try {
      const checkout = await createCheckout(orgId, plan);
      if (checkout.development && session?.demo) {
        await activateDemoPlan(orgId, plan);
        await refresh();
      } else if (checkout.development) {
        setError(
          "Stripe is not configured. A local administrator can activate the plan in development mode.",
        );
      } else if (checkout.url && stripeDestination(checkout.url)) {
        window.location.assign(checkout.url);
      } else {
        throw new Error("Stripe Checkout returned an invalid destination");
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not start checkout");
    } finally {
      setBusy(false);
    }
  }

  async function manage() {
    if (!orgId) return;
    setBusy(true);
    setError("");
    try {
      const portal = await createPortal(orgId);
      if (!stripeDestination(portal.url))
        throw new Error("Stripe portal returned an invalid destination");
      window.location.assign(portal.url);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not open billing portal");
    } finally {
      setBusy(false);
    }
  }

  if (error && !billing) return <ErrorState message={error} />;
  if (!billing || !org) return <LoadingState label="Loading billing..." />;
  const percent = billing.daily_limit
    ? Math.min(100, Math.round((billing.audits_today / billing.daily_limit) * 100))
    : 0;
  const owner = org.role === "owner";
  const currentPrice = tiers.find((tier) => tier.plan === billing.plan)?.price ?? 0;
  return (
    <>
      <PageHeader
        eyebrow="Workspace administration"
        title="Billing"
        description="Review audit usage, subscription, and invoices."
      />
      {error && (
        <div
          role="alert"
          className="mb-5 rounded-lg border border-rose-500/20 bg-rose-500/10 p-3 text-xs text-rose-300"
        >
          {error}
        </div>
      )}
      {billing.billing_status === "past_due" && (
        <div
          role="alert"
          className="mb-5 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200"
        >
          Payment is past due. Audits are paused until billing is updated.
        </div>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Current plan</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-6 pt-4 md:grid-cols-[1fr_1fr]">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck className="text-emerald-300" size={20} />
              <strong className="text-2xl capitalize">{billing.plan}</strong>
              <Badge>{billing.billing_status}</Badge>
            </div>
            <p className="mt-2 text-xs text-slate-400">
              {billing.seat_count} billed {billing.seat_count === 1 ? "developer" : "developers"}
            </p>
            {owner && billing.has_customer && (
              <Button className="mt-5" disabled={busy} onClick={manage}>
                <CreditCard size={15} /> Manage billing
              </Button>
            )}
          </div>
          <div>
            <div className="flex justify-between text-xs text-slate-300">
              <span>Audits today</span>
              <strong>
                {billing.audits_today.toLocaleString()} /{" "}
                {billing.daily_limit?.toLocaleString() ?? "Unlimited"}
              </strong>
            </div>
            <div
              role="progressbar"
              aria-valuenow={billing.audits_today}
              aria-valuemin={0}
              aria-valuemax={billing.daily_limit ?? undefined}
              className="mt-3 h-2 overflow-hidden rounded-full bg-white/10"
            >
              <div
                className="h-full rounded-full bg-emerald-400"
                style={{ width: `${percent}%` }}
              />
            </div>
            <p className="mt-3 text-[11px] text-slate-500">Usage resets at midnight UTC.</p>
          </div>
        </CardContent>
      </Card>
      <div className="mt-5 grid gap-4 md:grid-cols-3">
        {tiers.map((tier) => (
          <Card
            key={tier.plan}
            className={billing.plan === tier.plan ? "border-emerald-400/30" : ""}
          >
            <CardHeader>
              <CardTitle className="capitalize">{tier.plan}</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              <div className="text-3xl font-semibold">
                ${tier.price}
                <span className="text-xs font-normal text-slate-500"> / developer / month</span>
              </div>
              <p className="mt-3 text-xs text-emerald-300">{tier.quota}</p>
              <ul className="mt-4 min-h-28 space-y-2 text-xs text-slate-400">
                {tier.features.map((feature) => (
                  <li key={feature}>• {feature}</li>
                ))}
              </ul>
              {tier.plan !== "free" && (
                <Button
                  className="mt-4 w-full"
                  disabled={
                    !owner || busy || tier.price <= currentPrice || billing.has_subscription
                  }
                  onClick={() => upgrade(tier.plan)}
                >
                  {billing.plan === tier.plan
                    ? "Current plan"
                    : tier.price < currentPrice
                      ? "Included in current plan"
                    : `Upgrade to ${tier.plan === "pro" ? "Pro" : "Team"}`}
                </Button>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
      {owner && (
        <Card className="mt-5">
          <CardHeader>
            <CardTitle>Invoices</CardTitle>
          </CardHeader>
          <CardContent className="pt-3">
            {invoiceError && (
              <p role="alert" className="text-xs text-amber-300">
                {invoiceError}
              </p>
            )}
            {invoices.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-slate-500">
                    <tr>
                      <th className="py-3">Invoice</th>
                      <th>Date</th>
                      <th>Amount paid</th>
                      <th>Status</th>
                      <th>Receipt</th>
                    </tr>
                  </thead>
                  <tbody>
                    {invoices.map((invoice) => (
                      <tr key={invoice.id} className="border-t border-white/[.07]">
                        <td className="py-3">{invoice.number ?? invoice.id}</td>
                        <td>
                          {invoice.created
                            ? new Date(invoice.created * 1000).toLocaleDateString()
                            : "—"}
                        </td>
                        <td>
                          {new Intl.NumberFormat(undefined, {
                            style: "currency",
                            currency: invoice.currency.toUpperCase(),
                          }).format(invoice.amount_paid / 100)}
                        </td>
                        <td className="capitalize">{invoice.status ?? "Unknown"}</td>
                        <td>
                          {invoice.hosted_invoice_url &&
                          stripeDestination(invoice.hosted_invoice_url) ? (
                            <a
                              href={invoice.hosted_invoice_url}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 text-emerald-300"
                            >
                              View <ArrowUpRight size={12} />
                            </a>
                          ) : (
                            "—"
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              !invoiceError && <p className="text-xs text-slate-500">No invoices yet.</p>
            )}
          </CardContent>
        </Card>
      )}
    </>
  );
}
