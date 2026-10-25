import { Suspense } from "react"
import Link from "next/link"
import { redirect } from "next/navigation"
import { connection } from "next/server"
import { ApiError, apiGet } from "@/lib/api/client"
import type { ActNowItem, DashboardSummary } from "@/lib/api/types"
import { ActNowStack } from "@/components/overview/act-now-stack"
import { EmptyState } from "@/components/empty-state"
import { Skeleton } from "@/components/ui/skeleton"

export const metadata = { title: "Act now" }

async function tryGet<T>(path: string): Promise<T | null> {
  try {
    return await apiGet<T>(path)
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) redirect("/login")
    return null
  }
}

async function ActNowList() {
  await connection()

  const [actNow, summary] = await Promise.all([
    tryGet<ActNowItem[]>("/api/v1/dashboard/act-now?top=20&days=7"),
    tryGet<DashboardSummary>("/api/v1/dashboard/summary?days=7"),
  ])
  const hasFollows = (summary?.followedCount ?? 0) > 0

  if (actNow === null) {
    return (
      <EmptyState
        title="Act now unavailable"
        description="The priority list could not be loaded. Try refreshing."
      />
    )
  }

  if (!hasFollows) {
    return (
      <div className="flex flex-col gap-2">
        <EmptyState
          title="No technologies followed yet"
          description="Follow the technologies in your stack to see what you should patch first."
        />
        <p className="text-muted-foreground text-xs">
          <Link
            href="/technologies"
            className="text-primary hover:underline focus-visible:ring-primary/50 rounded-sm focus-visible:ring-2 focus-visible:outline-none"
          >
            Browse technologies to follow →
          </Link>
        </p>
      </div>
    )
  }

  if (actNow.length === 0) {
    return (
      <EmptyState
        title="Nothing needs action right now"
        description="No recent disclosures or newly exploited vulnerabilities matched technologies you follow."
      />
    )
  }

  return <ActNowStack items={actNow} showHeader={false} />
}

function Fallback() {
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className="h-28 w-full" />
      ))}
    </div>
  )
}

export default function ActNowPage() {
  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-base font-semibold">Act now</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          Highest-priority vulnerabilities in your stack, last 7 days.
        </p>
      </div>
      <Suspense fallback={<Fallback />}>
        <ActNowList />
      </Suspense>
    </div>
  )
}
