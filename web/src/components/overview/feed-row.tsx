import Link from "next/link"
import { Flame, Wrench } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { SeverityDot } from "@/components/severity-badge"
import { RelativeTime } from "@/components/relative-time"
import type { VulnerabilityListItem } from "@/lib/api/types"

export function FeedRow({ item }: { item: VulnerabilityListItem }) {
  return (
    <li className="flex min-w-0 items-center gap-3 border-b border-line py-2.5 last:border-b-0">
      <SeverityDot severity={item.severity} className="shrink-0" />
      <div className="min-w-0 flex-1">
        <Link
          href={`/vulnerabilities/${item.id}`}
          className="block truncate text-[13px] hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-sm"
        >
          {item.title}
        </Link>
        <p className="text-muted-foreground mt-0.5 font-mono text-[11px]">
          {item.canonicalId}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {item.isKnownExploited && (
          <Badge
            className="border-severity-high/30 bg-severity-high/10 text-severity-high gap-1"
            title="Known to be exploited (KEV)"
          >
            <Flame className="size-3" aria-hidden />
            KEV
          </Badge>
        )}
        {item.hasFix && (
          <Badge className="gap-1" variant="secondary" title="Fix available">
            <Wrench className="size-3" aria-hidden />
            Fix
          </Badge>
        )}
        <RelativeTime iso={item.publishedAt} />
      </div>
    </li>
  )
}
