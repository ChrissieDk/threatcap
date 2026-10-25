import { ExternalLink } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import { RelativeTime } from "@/components/relative-time"
import type { IncidentStatus, IncidentType, SecurityIncidentItem } from "@/lib/api/types"

const STATUS_CLASS: Record<IncidentStatus, string> = {
  Investigating: "border-severity-high/30 bg-severity-high/10 text-severity-high",
  Identified: "border-severity-medium/30 bg-severity-medium/10 text-severity-medium",
  Monitoring: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-400",
  Resolved: "border-line-strong bg-surface-2 text-muted-foreground",
}

const TYPE_LABEL: Record<IncidentType, string> = {
  Outage: "Outage",
  ServiceDegradation: "Degraded",
  ExploitationReported: "Exploitation",
  SecurityIncident: "Security",
  SuspectedSecurityIncident: "Suspected",
}

function byNewest(a: SecurityIncidentItem, b: SecurityIncidentItem) {
  return b.updatedAt.localeCompare(a.updatedAt) || b.startedAt.localeCompare(a.startedAt)
}

export function IncidentList({ items }: { items: SecurityIncidentItem[] }) {
  const active = items.filter((item) => item.status !== "Resolved").sort(byNewest)
  const resolved = items.filter((item) => item.status === "Resolved").sort(byNewest)

  return (
    <div className="flex flex-col gap-6">
      <IncidentSection
        title="Active"
        empty="No active vendor incidents for technologies you follow."
        items={active}
      />
      <IncidentSection
        title="Recently resolved"
        empty="No resolved incidents in this window."
        items={resolved}
      />
    </div>
  )
}

function IncidentSection({
  title,
  empty,
  items,
}: {
  title: string
  empty: string
  items: SecurityIncidentItem[]
}) {
  return (
    <section aria-label={title}>
      <h2 className="text-sm font-medium">
        {title}
        <span className="text-muted-foreground ml-1.5 text-xs font-normal tabular-nums">
          {items.length}
        </span>
      </h2>
      {items.length === 0 ? (
        <p className="text-muted-foreground mt-2 text-xs">{empty}</p>
      ) : (
        <ul className="border-line mt-2 divide-y divide-line rounded-md border">
          {items.map((item) => (
            <IncidentRow key={item.id} item={item} />
          ))}
        </ul>
      )}
    </section>
  )
}

function IncidentRow({ item }: { item: SecurityIncidentItem }) {
  const title = (
    <span className="min-w-0 truncate text-[13px] font-medium">{item.title}</span>
  )

  return (
    <li className="flex flex-col gap-1.5 px-3 py-2.5">
      <div className="flex items-center gap-2">
        <Badge variant="outline" className="font-mono text-[10px] uppercase">
          {item.vendorName}
        </Badge>
        <span
          className={cn(
            "inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-medium",
            STATUS_CLASS[item.status]
          )}
        >
          {item.status}
        </span>
        <span className="text-muted-foreground text-[11px]">
          {TYPE_LABEL[item.type]}
        </span>
        {item.url ? (
          <a
            href={item.url}
            target="_blank"
            rel="noreferrer"
            className="flex min-w-0 flex-1 items-center gap-1.5 hover:text-primary focus-visible:ring-primary/50 rounded-sm focus-visible:ring-2 focus-visible:outline-none"
          >
            {title}
            <ExternalLink className="text-muted-foreground size-3 shrink-0" aria-hidden />
          </a>
        ) : (
          <div className="min-w-0 flex-1">{title}</div>
        )}
        <RelativeTime iso={item.updatedAt} className="ml-auto" />
      </div>
      {item.description && (
        <p className="text-muted-foreground line-clamp-2 text-xs">{item.description}</p>
      )}
    </li>
  )
}
