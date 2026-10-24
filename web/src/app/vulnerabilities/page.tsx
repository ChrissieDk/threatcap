import { Suspense } from "react"
import { VulnExplorer } from "@/components/vulnerabilities/vuln-explorer"
import { Skeleton } from "@/components/ui/skeleton"

function Fallback() {
  return (
    <div className="flex flex-col gap-4">
      <Skeleton className="h-5 w-40" />
      <Skeleton className="h-8 w-full max-w-md" />
      <div className="flex flex-col gap-2">
        {Array.from({ length: 10 }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </div>
    </div>
  )
}

export default function VulnerabilitiesPage() {
  return (
    <Suspense fallback={<Fallback />}>
      <VulnExplorer />
    </Suspense>
  )
}
