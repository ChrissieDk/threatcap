import { Inbox } from "lucide-react"

export function EmptyState({
  title,
  description,
}: {
  title: string
  description: string
}) {
  return (
    <div className="border-line flex flex-col items-center justify-center gap-2 rounded-md border border-dashed px-6 py-12 text-center">
      <Inbox className="text-muted-foreground size-5" aria-hidden />
      <p className="text-sm font-medium">{title}</p>
      <p className="text-muted-foreground max-w-sm text-xs">{description}</p>
    </div>
  )
}

export function ComingSoon({ feature }: { feature: string }) {
  return (
    <EmptyState
      title={`${feature} is not available yet`}
      description="This part of Threatwatch is coming in a later phase. Check back after the next release."
    />
  )
}
