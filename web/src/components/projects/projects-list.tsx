"use client"

import Link from "next/link"
import { Flame } from "lucide-react"
import { RelativeTime } from "@/components/relative-time"
import type { ProjectSummary } from "@/lib/api/types"

export function ProjectsList({ projects }: { projects: ProjectSummary[] }) {
  if (projects.length === 0) {
    return <p className="text-muted-foreground text-xs">No projects yet. Add your first one above.</p>
  }

  return (
    <div className="flex flex-col gap-4">
      {projects.length > 0 && (
        <ul className="border-line divide-line divide-y rounded-md border">
          {projects.map((p) => (
            <li key={p.id}>
              <Link
                href={`/projects/${p.id}`}
                className="hover:bg-surface focus-visible:ring-primary/50 flex items-center gap-3 px-3 py-2.5 focus-visible:ring-2 focus-visible:outline-none"
              >
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[13px] font-medium">{p.name}</p>
                  <p className="text-muted-foreground mt-0.5 text-[11px]">
                    {p.dependencyCount} dependencies · {p.sourceFiles.join(", ")}
                  </p>
                </div>
                {p.knownExploitedCount > 0 && (
                  <Flame className="text-severity-high size-3.5 shrink-0" aria-label="Contains actively exploited vulnerabilities" />
                )}
                <span
                  className={`rounded-md border px-1.5 py-0.5 text-[11px] font-medium ${
                    p.findingCount === 0 ? "border-line text-muted-foreground" : "border-severity-high/40 text-severity-high"
                  }`}
                >
                  {p.findingCount === 0 ? "No known issues" : `${p.findingCount} affected`}
                </span>
                <RelativeTime iso={p.updatedAt} />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
