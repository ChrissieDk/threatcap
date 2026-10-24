"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import type { DailyMetric, DailyPoint } from "@/lib/api/types"
import { endSession } from "@/lib/auth"

const METRICS: Array<{ value: DailyMetric; label: string }> = [
  { value: "disclosures", label: "Disclosures" },
  { value: "updates", label: "Updates" },
  { value: "kev", label: "KEV additions" },
]

const METRIC_NOUNNS: Record<DailyMetric, string> = {
  disclosures: "New vulnerability disclosures",
  updates: "Advisory updates",
  kev: "KEV additions",
  incidents: "Active incidents",
}

export function ActivityChart({
  initialDays,
  initialData,
  following = false,
}: {
  initialDays: number
  initialData: DailyPoint[]
  following?: boolean
}) {
  const [days, setDays] = useState(initialDays)
  const [metric, setMetric] = useState<DailyMetric>("disclosures")
  const [data, setData] = useState(initialData)
  const [loading, setLoading] = useState(false)
  const router = useRouter()

  async function load(nextDays: number, nextMetric: DailyMetric) {
    setLoading(true)
    try {
      const res = await fetch(
        `/api/v1/dashboard/daily?days=${nextDays}&metric=${nextMetric}${following ? "&following=true" : ""}`,
        { signal: AbortSignal.timeout(20_000) }
      )
      if (res.status === 401) {
        await endSession()
        router.push("/login")
        router.refresh()
        return
      }
      if (res.ok) {
        setData((await res.json()) as DailyPoint[])
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <section
      aria-label="Activity over time"
      className="border-line bg-surface rounded-md border p-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium">Activity</h2>
          <p className="text-muted-foreground mt-0.5 text-xs">
            {METRIC_NOUNNS[metric]}, last {days} days (UTC)
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Tabs
            value={metric}
            onValueChange={(v) => {
              const m = v as DailyMetric
              setMetric(m)
              void load(days, m)
            }}
          >
            <TabsList>
              {METRICS.map((m) => (
                <TabsTrigger key={m.value} value={m.value}>
                  {m.label}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
          <Tabs
            value={String(days)}
            onValueChange={(v) => {
              const d = Number(v)
              setDays(d)
              void load(d, metric)
            }}
          >
            <TabsList>
              {[7, 30, 90].map((d) => (
                <TabsTrigger key={d} value={String(d)}>
                  {d}d
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </div>
      </div>
      <div
        className="mt-4 h-56"
        aria-busy={loading}
      >
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
            <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
            <XAxis
              dataKey="date"
              tickFormatter={(d: string) => d.slice(5)}
              tick={{ fill: "var(--color-muted-foreground)", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              minTickGap={24}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: "var(--color-muted-foreground)", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--color-surface-2)",
                border: "1px solid var(--color-line)",
                borderRadius: 6,
                fontSize: 12,
              }}
              labelStyle={{ color: "var(--color-muted-foreground)" }}
              itemStyle={{ color: "var(--color-foreground)" }}
            />
            <Area
              type="monotone"
              dataKey="count"
              stroke="var(--chart-primary)"
              strokeWidth={1.5}
              fill="var(--chart-primary)"
              fillOpacity={0.12}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}
