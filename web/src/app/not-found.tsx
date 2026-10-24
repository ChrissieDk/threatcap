import Link from "next/link"
import { Button } from "@/components/ui/button"

export default function NotFound() {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center">
      <p className="text-sm font-medium">Page not found</p>
      <p className="text-muted-foreground max-w-sm text-xs">
        The page you are looking for does not exist.
      </p>
      <Button variant="outline" size="sm" asChild>
        <Link href="/">Back to overview</Link>
      </Button>
    </div>
  )
}
