import Link from "next/link"
import type { DashboardSummary } from "@/lib/api/types"
import { LastSyncControl } from "@/components/overview/last-sync-control"

function Metric({
  label,
  value,
  hint,
}: {
  label: string
  value: string
  hint?: React.ReactNode
}) {
  return (
    <div className="min-w-0">
      <p className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
        {label}
      </p>
      <p className="mt-0.5 flex items-baseline gap-1.5 text-lg font-semibold tabular-nums">
        {value}
        {hint}
      </p>
    </div>
  )
}

export function MetricStrip({
  summary,
  scoped,
}: {
  summary: DashboardSummary
  scoped?: boolean
}) {
  const lastSync = summary.lastSyncs
    .map((s) => s.lastSuccessfulSyncAt)
    .filter((d): d is string => d !== null)
    .sort()
    .at(-1)
  const hasError = summary.lastSyncs.some((s) => s.lastError)

  return (
    <section aria-label="Summary metrics" className="flex flex-wrap gap-x-8 gap-y-4">
      <Metric
        label={scoped ? "New in stack (7d)" : "New (7d)"}
        value={String(summary.newVulnerabilities)}
      />
      <Metric label="Critical / High" value={String(summary.criticalHigh)} />
      <Metric label="KEV added" value={String(summary.kevAdded)} />
      <Metric
        label="Followed with activity"
        value={String(summary.followedTopicsWithActivity)}
        hint={
          <Link
            href="/following"
            className="text-primary text-[11px] font-normal hover:underline focus-visible:ring-primary/50 rounded-sm focus-visible:ring-2 focus-visible:outline-none"
          >
            View
          </Link>
        }
      />
      <Metric
        label="Active incidents"
        value={String(summary.activeIncidents)}
        hint={
          <Link
            href="/incidents"
            className="text-primary text-[11px] font-normal hover:underline focus-visible:ring-primary/50 rounded-sm focus-visible:ring-2 focus-visible:outline-none"
          >
            View
          </Link>
        }
      />
      <LastSyncControl lastSyncAt={lastSync ?? null} hasError={hasError} />
    </section>
  )
}
