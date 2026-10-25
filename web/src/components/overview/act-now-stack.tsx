import Link from "next/link"
import { Flame } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { SeverityBadge } from "@/components/severity-badge"
import { ProductBadge } from "@/components/product-badge"
import { RelativeTime } from "@/components/relative-time"
import type { ActNowItem } from "@/lib/api/types"

function exploitationChance(item: ActNowItem): string | null {
  const probability = item.epssScore ?? item.epssPercentile
  if (probability === null) return null
  return `${Math.round(probability * 100)}% chance of exploitation in next 30 days`
}

export function ActNowCard({ item }: { item: ActNowItem }) {
  return (
    <li className="border-line bg-surface flex flex-col gap-2 rounded-md border p-3">
      <div className="flex min-w-0 items-center gap-2">
        <Link
          href={`/vulnerabilities/${item.id}`}
          className="block min-w-0 truncate text-[13px] font-medium hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-sm"
        >
          {item.title}
        </Link>
        <span className="text-muted-foreground shrink-0 font-mono text-[11px]">
          {item.canonicalId}
        </span>
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        <SeverityBadge severity={item.severity} />
        <ProductBadge
          primaryVendor={item.primaryVendor}
          primaryProduct={item.primaryProduct}
          productType={item.productType}
          className="max-w-40"
        />
        {item.isKnownExploited && (
          <Badge
            className="border-severity-high/30 bg-severity-high/10 text-severity-high gap-1"
            title="Known to be exploited (KEV)"
          >
            <Flame className="size-3" aria-hidden />
            KEV
          </Badge>
        )}
      </div>
      <div className="flex items-center justify-between gap-2">
        <span className="text-muted-foreground min-w-0 truncate text-[11px] tabular-nums">
          {item.priorityScore !== null && (
            <>Priority {item.priorityScore.toFixed(1)}</>
          )}
          {item.priorityScore !== null && exploitationChance(item) && " · "}
          {exploitationChance(item)}
        </span>
        <RelativeTime iso={item.publishedAt} />
      </div>
    </li>
  )
}

export function ActNowStack({
  items,
  showHeader = true,
}: {
  items: ActNowItem[]
  showHeader?: boolean
}) {
  return (
    <section aria-label="Act now">
      {showHeader && (
        <>
          <h2 className="text-sm font-medium">Act now</h2>
          <p className="text-muted-foreground mt-0.5 text-xs">
            Highest-priority vulnerabilities affecting technologies you follow.
          </p>
        </>
      )}
      <ul className={showHeader ? "mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-3" : "grid gap-3 sm:grid-cols-2 xl:grid-cols-3"}>
        {items.map((item) => (
          <ActNowCard key={item.id} item={item} />
        ))}
      </ul>
    </section>
  )
}
