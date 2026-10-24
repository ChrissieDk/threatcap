import Link from "next/link"
import { Button } from "@/components/ui/button"

export default function NotFound() {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center">
      <p className="text-sm font-medium">Vulnerability not found</p>
      <p className="text-muted-foreground max-w-sm text-xs">
        This vulnerability does not exist or has not been ingested yet.
      </p>
      <Button variant="outline" size="sm" asChild>
        <Link href="/vulnerabilities">Back to vulnerabilities</Link>
      </Button>
    </div>
  )
}
