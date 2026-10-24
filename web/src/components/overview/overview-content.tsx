import { ApiError, apiGet } from "@/lib/api/client"
import type {
  DailyPoint,
  DashboardSummary,
  Severity,
  VulnerabilityListResponse,
} from "@/lib/api/types"
import { MetricStrip } from "@/components/overview/metric-strip"
import { ActivityChart } from "@/components/overview/activity-chart"
import { FeedRow } from "@/components/overview/feed-row"
import { EmptyState } from "@/components/empty-state"
import { SEVERITY_META } from "@/lib/formatters"
import { cn } from "@/lib/utils"
import { connection } from "next/server"
import { redirect } from "next/navigation"
import Link from "next/link"

const DAYS = 7
const PAGE_SIZE = 100

function sevenDaysAgo(): string {
  const d = new Date(Date.now() - DAYS * 86_400_000)
  return d.toISOString().slice(0, 10)
}

async function tryGet<T>(path: string): Promise<T | null> {
  try {
    return await apiGet<T>(path)
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) redirect("/login")
    return null
  }
}

export async function OverviewContent({ scope }: { scope?: string }) {
  await connection()

  const baseline = await tryGet<DashboardSummary>(`/api/v1/dashboard/summary?days=${DAYS}`)
  const hasFollows = (baseline?.followedCount ?? 0) > 0
  const scoped = hasFollows && scope !== "all"
  const followQs = scoped ? "&following=true" : ""

  const [summary, daily, vulns] = await Promise.all([
    scoped
      ? tryGet<DashboardSummary>(`/api/v1/dashboard/summary?days=${DAYS}${followQs}`)
      : Promise.resolve(baseline),
    tryGet<DailyPoint[]>(`/api/v1/dashboard/daily?days=${DAYS}&metric=disclosures${followQs}`),
    tryGet<VulnerabilityListResponse>(
      `/api/v1/vulnerabilities?from=${sevenDaysAgo()}&page=1&pageSize=${PAGE_SIZE}&sort=-severity${followQs}`
    ),
  ])

  if (!summary && !vulns) {
    throw new ApiError(0, "Failed to load dashboard data")
  }

  // Severity distribution from the last-7-day vulnerability window
  const severityCounts = new Map<Severity, number>()
  const ecoCounts = new Map<string, number>()
  for (const v of vulns?.items ?? []) {
    severityCounts.set(v.severity, (severityCounts.get(v.severity) ?? 0) + 1)
    for (const eco of v.ecosystems) {
      ecoCounts.set(eco, (ecoCounts.get(eco) ?? 0) + 1)
    }
  }
  const totalInWindow = vulns?.total ?? 0
  const maxSeverity = Math.max(1, ...severityCounts.values())
  const topEcosystems = [...ecoCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
  const maxEco = Math.max(1, ...topEcosystems.map(([, c]) => c))

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-base font-semibold">Overview</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          {scoped
            ? `Activity for technologies you follow, last ${DAYS} days.`
            : `Security intelligence across tracked sources, last ${DAYS} days.`}
          {hasFollows && (
            <>
              {" "}
              <Link
                href={scoped ? "/?scope=all" : "/?scope=following"}
                className="text-primary hover:underline focus-visible:ring-primary/50 rounded-sm focus-visible:ring-2 focus-visible:outline-none"
              >
                {scoped ? "Show everything" : "Show my stack"}
              </Link>
            </>
          )}
        </p>
      </div>

      {summary ? (
        <MetricStrip summary={summary} scoped={scoped} />
      ) : (
        <p className="text-muted-foreground text-xs">Summary unavailable — the API could not be reached.</p>
      )}

      {daily ? (
        <ActivityChart initialDays={DAYS} initialData={daily} following={scoped} />
      ) : (
        <EmptyState
          title="Activity chart unavailable"
          description="The daily activity series could not be loaded. The rest of the overview is still using the data that did load."
        />
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <section
          aria-label="Severity distribution"
          className="border-line bg-surface rounded-md border p-4"
        >
          <h2 className="text-sm font-medium">Severity distribution</h2>
          <p className="text-muted-foreground mt-0.5 text-xs">
            {scoped ? "New in your stack" : "New in the last"} {DAYS} days by severity
            {totalInWindow > PAGE_SIZE ? " (top 100 shown)" : ""}.
          </p>
          {vulns === null ? (
            <div className="mt-4">
              <EmptyState
                title="Severity data unavailable"
                description="The vulnerability request failed. The count above reflects an error, not an empty result — try refreshing."
              />
            </div>
          ) : severityCounts.size === 0 ? (
            <div className="mt-4">
              <EmptyState
                title={scoped ? "No matching advisories" : "No vulnerabilities ingested yet"}
                description={
                  scoped
                    ? "Nothing in your stack was disclosed in this window. Try Show everything, or follow another technology."
                    : "The ingestion worker may still be running. Data will appear here after the first sync."
                }
              />
            </div>
          ) : (
            <ul className="mt-4 flex flex-col gap-2.5">
              {(Object.keys(SEVERITY_META) as Severity[]).map((sev) => {
                const count = severityCounts.get(sev) ?? 0
                return (
                  <li key={sev} className="flex items-center gap-3">
                    <span className="w-14 shrink-0 text-xs">{SEVERITY_META[sev].label}</span>
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-surface-2">
                      <div
                        className={cn("h-full rounded-full", SEVERITY_META[sev].dotClass)}
                        style={{ width: `${(count / maxSeverity) * 100}%` }}
                      />
                    </div>
                    <span className="w-8 shrink-0 text-right text-xs tabular-nums">{count}</span>
                  </li>
                )
              })}
            </ul>
          )}
        </section>

        <section
          aria-label="Ecosystem breakdown"
          className="border-line bg-surface rounded-md border p-4"
        >
          <h2 className="text-sm font-medium">Ecosystems</h2>
          <p className="text-muted-foreground mt-0.5 text-xs">
            Affected package ecosystems in the last {DAYS} days
            {scoped ? " for technologies you follow" : ""}.
          </p>
          {vulns === null ? (
            <div className="mt-4">
              <EmptyState
                title="Ecosystem data unavailable"
                description="The vulnerability request failed. This reflects an error, not an empty result — try refreshing."
              />
            </div>
          ) : topEcosystems.length === 0 ? (
            <div className="mt-4">
              <EmptyState
                title={scoped ? "No matching ecosystems" : "No ecosystems tracked yet"}
                description={
                  scoped
                    ? "Followed technologies had no affected packages in this window."
                    : "Ecosystem breakdown appears once vulnerabilities with affected packages are ingested."
                }
              />
            </div>
          ) : (
            <ul className="mt-4 flex flex-col gap-2.5">
              {topEcosystems.map(([eco, count]) => (
                <li key={eco} className="flex items-center gap-3">
                  <Link
                    href={`/vulnerabilities?ecosystem=${encodeURIComponent(eco)}`}
                    className="w-24 shrink-0 truncate text-xs hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-sm"
                  >
                    {eco}
                  </Link>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-surface-2">
                    <div
                      className="bg-primary h-full rounded-full"
                      style={{ width: `${(count / maxEco) * 100}%` }}
                    />
                  </div>
                  <span className="w-8 shrink-0 text-right text-xs tabular-nums">{count}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section
        aria-label="Latest activity"
        className="border-line bg-surface rounded-md border p-4"
      >
        <h2 className="text-sm font-medium">Latest activity</h2>
        <p className="text-muted-foreground mt-0.5 text-xs">
          {scoped
            ? "Highest-severity matching advisories in your stack."
            : "Most recently published vulnerabilities."}
        </p>
        {vulns === null ? (
          <div className="mt-4">
            <EmptyState
              title="Activity feed unavailable"
              description="The vulnerability request failed. This reflects an error, not an empty result — try refreshing."
            />
          </div>
        ) : vulns.items.length === 0 ? (
          <div className="mt-4">
            <EmptyState
              title={scoped ? "No matching advisories" : "No vulnerabilities ingested yet"}
              description={
                scoped
                  ? "Highest-severity matching advisories will show here when your stack has new disclosures."
                  : "The ingestion worker may still be running. Data will appear here after the first sync."
              }
            />
          </div>
        ) : (
          <ul className="mt-2">
            {(vulns?.items ?? []).slice(0, 10).map((v) => (
              <FeedRow key={v.id} item={v} />
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
