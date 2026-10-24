import { SEVERITY_META } from "@/lib/formatters"
import { cn } from "@/lib/utils"
import type { Severity } from "@/lib/api/types"

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity
  className?: string
}) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.Unknown
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-[11px] font-medium",
        meta.badgeClass,
        className
      )}
    >
      <span className={cn("size-1.5 rounded-full", meta.dotClass)} aria-hidden />
      {meta.label}
    </span>
  )
}

export function SeverityDot({
  severity,
  className,
}: {
  severity: Severity
  className?: string
}) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.Unknown
  return (
    <span
      className={cn("inline-block size-1.5 rounded-full", meta.dotClass, className)}
      title={meta.label}
    />
  )
}
