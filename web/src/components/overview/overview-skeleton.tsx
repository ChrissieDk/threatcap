import { Skeleton } from "@/components/ui/skeleton"

export function OverviewSkeleton() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <Skeleton className="h-5 w-28" />
        <Skeleton className="mt-2 h-3 w-64" />
      </div>
      <div className="flex gap-8">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i}>
            <Skeleton className="h-2.5 w-16" />
            <Skeleton className="mt-2 h-6 w-10" />
          </div>
        ))}
      </div>
      <Skeleton className="h-72 w-full" />
      <div className="grid gap-4 lg:grid-cols-2">
        <Skeleton className="h-64 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
      <Skeleton className="h-72 w-full" />
    </div>
  )
}
