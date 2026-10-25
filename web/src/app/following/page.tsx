import { Suspense } from "react"
import { redirect } from "next/navigation"
import Link from "next/link"
import { Flame } from "lucide-react"
import { ApiError, apiGet } from "@/lib/api/client"
import type { FollowedTechnology } from "@/lib/api/types"
import { FollowButton } from "@/components/technologies/follow-button"
import { EmptyState } from "@/components/empty-state"
import { Skeleton } from "@/components/ui/skeleton"
import { RelativeTime } from "@/components/relative-time"
import { connection } from "next/server"

export const metadata = { title: "Following" }

const DAYS = 7

async function FollowingList() {
  await connection()
  let items: FollowedTechnology[] = []
  try {
    items = await apiGet<FollowedTechnology[]>(`/api/v1/follows?days=${DAYS}`)
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) redirect("/login")
    return (
      <EmptyState
        title="Could not load follows"
        description="The API may be unavailable. Try again in a moment."
      />
    )
  }

  if (items.length === 0) {
    return (
      <EmptyState
        title="You are not following anything yet"
        description="Pick languages, frameworks, packages, or ecosystems from the catalog to see their recent advisories here."
      />
    )
  }

  return (
    <ul className="border-line divide-y divide-line rounded-md border">
      {items.map((item) => (
        <li key={item.slug} className="flex items-center gap-3 px-3 py-2.5">
          <Link
            href={`/vulnerabilities?tech=${encodeURIComponent(item.slug)}`}
            className="min-w-0 flex-1 rounded-sm hover:text-primary focus-visible:ring-primary/50 focus-visible:ring-2 focus-visible:outline-none"
          >
            <p className="truncate text-[13px] font-medium">{item.name}</p>
            <p className="text-muted-foreground mt-0.5 text-[11px]">
              {item.ecosystemWide
                ? `Entire ${item.ecosystem} ecosystem`
                : item.ecosystem
                  ? `${item.type} · ${item.ecosystem}`
                  : item.type}
              {" · "}
              {item.recentActivityCount === 0
                ? `No new advisories in ${DAYS}d`
                : `${item.recentActivityCount} new in ${DAYS}d`}
              {item.kevCount > 0 ? ` · ${item.kevCount} KEV` : ""}
              {item.criticalHighCount > 0 ? ` · ${item.criticalHighCount} critical/high` : ""}
            </p>
          </Link>
          {item.lastActivityAt && <RelativeTime iso={item.lastActivityAt} />}
          {item.kevCount > 0 && (
            <Flame className="text-severity-high size-3.5 shrink-0" aria-label="Has KEV activity" />
          )}
          <FollowButton slug={item.slug} following name={item.name} />
        </li>
      ))}
    </ul>
  )
}

function Fallback() {
  return (
    <div className="flex flex-col gap-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className="h-11 w-full" />
      ))}
    </div>
  )
}

export default function FollowingPage() {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold">Following</h1>
          <p className="text-muted-foreground mt-0.5 text-xs">
            Your stack, ranked by KEV and severity. Open a row to see matching advisories.
          </p>
        </div>
        <Link
          href="/technologies"
          className="text-primary text-xs hover:underline focus-visible:ring-primary/50 rounded-sm focus-visible:ring-2 focus-visible:outline-none"
        >
          Browse catalog
        </Link>
      </div>
      <Suspense fallback={<Fallback />}>
        <FollowingList />
      </Suspense>
    </div>
  )
}
