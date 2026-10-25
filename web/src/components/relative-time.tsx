import { Clock } from "lucide-react"
import { cn } from "@/lib/utils"
import { formatRelativeTime, formatUtcDate, relativeAge } from "@/lib/formatters"

const AGE_CLASS = {
  fresh: "border-primary/40 bg-primary/15 text-foreground",
  recent: "border-line-strong bg-surface-2 text-foreground",
  older: "border-line-strong bg-surface-2 text-foreground",
  unknown: "border-line-strong bg-surface-2 text-foreground",
} as const

export function RelativeTime({
  iso,
  className,
}: {
  iso: string | null | undefined
  className?: string
}) {
  const label = formatRelativeTime(iso)
  const exact = formatUtcDate(iso)
  const age = relativeAge(iso)

  return (
    <time
      dateTime={iso ?? undefined}
      title={exact === "—" ? undefined : exact}
      className={cn(
        "inline-flex w-max shrink-0 items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-0.5 text-[11px] font-medium tabular-nums",
        AGE_CLASS[age],
        className
      )}
    >
      <Clock className="size-3 opacity-80" aria-hidden />
      {label}
    </time>
  )
}
