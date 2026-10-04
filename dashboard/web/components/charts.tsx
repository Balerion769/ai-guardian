"use client";

import {
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { CategoryCount, DailyRisk } from "@/lib/types";

export function RiskOverTimeChart({ data }: { data: DailyRisk[] }) {
  if (!data.length)
    return (
      <div className="flex h-60 items-center justify-center text-sm text-slate-500">
        No completed audits yet.
      </div>
    );
  return (
    <div className="h-60 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 14, right: 10, left: -20, bottom: 0 }}>
          <XAxis
            dataKey="date"
            tickFormatter={(value: string) => value.slice(5)}
            stroke="#667282"
            tickLine={false}
            axisLine={false}
            fontSize={11}
          />
          <YAxis
            domain={[0, 100]}
            stroke="#667282"
            tickLine={false}
            axisLine={false}
            fontSize={11}
          />
          <Tooltip
            contentStyle={{
              background: "#171d25",
              border: "1px solid #3b4653",
              borderRadius: 10,
              color: "#e6edf3",
            }}
            formatter={(value) => [`${value ?? 0} / 100`, "Average risk"]}
          />
          <Line
            type="monotone"
            dataKey="average_risk_score"
            stroke="#4ade9a"
            strokeWidth={2.5}
            dot={{ fill: "#4ade9a", r: 3 }}
            activeDot={{ r: 6 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

const palette = ["#50d49a", "#f4b860", "#fa7b7b", "#79a7f2", "#ad94ed", "#65c3d2"];
export function FindingsByCategory({ data }: { data: CategoryCount[] }) {
  if (!data.length)
    return (
      <div className="flex h-60 items-center justify-center text-sm text-slate-500">
        No findings to categorize.
      </div>
    );
  return (
    <div className="flex flex-col items-center gap-3 sm:flex-row">
      <div className="h-52 w-52 shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="count"
              nameKey="category"
              innerRadius={58}
              outerRadius={82}
              paddingAngle={3}
              stroke="none"
            >
              {data.map((entry, index) => (
                <Cell key={entry.category} fill={palette[index % palette.length]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: "#171d25",
                border: "1px solid #3b4653",
                borderRadius: 10,
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="w-full space-y-2">
        {data.slice(0, 6).map((item, index) => (
          <div key={item.category} className="flex items-center justify-between gap-3 text-xs">
            <span className="flex min-w-0 items-center gap-2 text-slate-400">
              <span
                className="h-2 w-2 shrink-0 rounded-full"
                style={{ background: palette[index % palette.length] }}
              />
              <span className="truncate">{item.category}</span>
            </span>
            <span className="mono text-slate-200">{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function RiskSparkline({ scores }: { scores: number[] }) {
  if (!scores.length) return <span className="text-xs text-slate-600">No data</span>;
  return (
    <div className="h-8 w-24">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={scores.map((score, index) => ({ index, score }))}>
          <Line type="monotone" dataKey="score" stroke="#70dca5" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
