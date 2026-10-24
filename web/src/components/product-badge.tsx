import { cn } from "@/lib/utils"
import type { ProductType } from "@/lib/api/types"

const PRODUCT_TYPE_META: Record<
  ProductType,
  { tagClass: string }
> = {
  Library: {
    tagClass: "text-sky-700 dark:text-sky-400",
  },
  App: {
    tagClass: "text-emerald-700 dark:text-emerald-400",
  },
  Os: {
    tagClass: "text-violet-700 dark:text-violet-400",
  },
  Service: {
    tagClass: "text-amber-700 dark:text-amber-400",
  },
  Other: {
    tagClass: "text-muted-foreground",
  },
}

export function ProductBadge({
  primaryVendor,
  primaryProduct,
  productType,
  className,
}: {
  primaryVendor: string | null
  primaryProduct: string | null
  productType: ProductType | null
  className?: string
}) {
  if (!primaryVendor && !primaryProduct) {
    return (
      <span className="text-muted-foreground text-xs">—</span>
    )
  }

  const meta = productType
    ? PRODUCT_TYPE_META[productType]
    : PRODUCT_TYPE_META.Other
  const tag = primaryVendor ?? ""

  return (
    <span
      className={cn(
        "border-line-strong bg-surface-2 inline-flex max-w-full items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-[11px] font-medium",
        className
      )}
      title={[primaryVendor, primaryProduct].filter(Boolean).join(" / ")}
    >
      {tag && (
        <span
          className={cn("font-mono text-[10px] uppercase", meta.tagClass)}
        >
          [{tag}]
        </span>
      )}
      <span className="truncate">{primaryProduct ?? "Unknown product"}</span>
    </span>
  )
}
