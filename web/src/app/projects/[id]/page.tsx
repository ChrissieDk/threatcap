import { Suspense } from "react"
import Link from "next/link"
import { notFound, redirect } from "next/navigation"
import { connection } from "next/server"
import { ChevronLeft, Flame } from "lucide-react"
import { ApiError, apiGet } from "@/lib/api/client"
import type { ProjectDetail } from "@/lib/api/types"
import { EmptyState } from "@/components/empty-state"
import { ProjectActions } from "@/components/projects/project-actions"
import { RelativeTime } from "@/components/relative-time"
import { SeverityBadge } from "@/components/severity-badge"
import { Skeleton } from "@/components/ui/skeleton"

export const metadata = { title: "Project" }

async function Detail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  await connection()
  let detail: ProjectDetail
  try {
    detail = await apiGet<ProjectDetail>(`/api/v1/projects/${encodeURIComponent(id)}`)
  } catch (error) {
    if (error instanceof ApiError) {
      if (error.status === 401) redirect("/login")
      if (error.status === 404) notFound()
    }
    return (
      <EmptyState
        title="Could not load this project"
        description="The API may be unavailable. Try again in a moment."
      />
    )
  }

  const { summary, findings, dependencies } = detail
  const approximate = findings.some((f) => f.versionKind === "Declared")
  const direct = dependencies.filter((d) => d.isDirect)

  return (
    <div className="flex flex-col gap-5">
      <div>
        <Link href="/projects" className="text-muted-foreground hover:text-foreground mb-2 inline-flex items-center gap-1 text-xs">
          <ChevronLeft className="size-3.5" aria-hidden /> Projects
        </Link>
        <h1 className="text-base font-semibold">{summary.name}</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          {summary.dependencyCount} dependencies ({summary.directCount} direct) · {summary.sourceFiles.join(", ")} · updated{" "}
          <RelativeTime iso={summary.updatedAt} />
        </p>
      </div>

      <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label="Affected" value={summary.findingCount} />
        <Stat label="Critical / high" value={summary.criticalHighCount} />
        <Stat label="Actively exploited" value={summary.knownExploitedCount} />
        <Stat label="Version unknown" value={summary.uncheckedCount} />
      </dl>

      {approximate && (
        <p className="border-line bg-surface rounded-md border px-3 py-2 text-xs">
          Some results use the lowest version your declared range allows, so you may already be on a fixed one.
          Add a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.lock) for exact results.
        </p>
      )}

      <section aria-labelledby="findings-heading" className="flex flex-col gap-2">
        <h2 id="findings-heading" className="text-sm font-semibold">Known vulnerabilities</h2>
        {findings.length === 0 ? (
          <EmptyState
            title="No known vulnerabilities"
            description="None of the dependency versions we could check match an advisory we have. New advisories are checked automatically."
          />
        ) : (
          <ul className="border-line divide-line divide-y rounded-md border">
            {findings.map((f) => (
              <li key={`${f.vulnerabilityId}:${f.package}:${f.version}`} className="flex items-start gap-3 px-3 py-2.5">
                <SeverityBadge severity={f.severity} className="mt-0.5" />
                <div className="min-w-0 flex-1">
                  <Link href={`/vulnerabilities/${f.vulnerabilityId}`} className="hover:text-primary text-[13px] font-medium">
                    {f.canonicalId}
                  </Link>
                  <p className="text-muted-foreground truncate text-[11px]">{f.title}</p>
                  <p className="mt-1 text-[11px]">
                    <code className="bg-surface rounded px-1">{f.package}</code> {f.versionKind === "Declared" ? "≥ " : ""}
                    {f.version}
                    {f.fixedIn ? <> → <span className="text-emerald-600">upgrade to {f.fixedIn}</span></> : <span className="text-muted-foreground"> · no fixed version listed</span>}
                    {!f.isDirect && <span className="text-muted-foreground"> · indirect</span>}
                    {f.isDev && <span className="text-muted-foreground"> · dev only</span>}
                  </p>
                </div>
                {f.isKnownExploited && <Flame className="text-severity-high size-3.5 shrink-0" aria-label="Actively exploited" />}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="deps-heading" className="flex flex-col gap-2">
        <details className="border-line rounded-md border">
          <summary id="deps-heading" className="cursor-pointer px-3 py-2 text-sm font-semibold">
            Direct dependencies ({direct.length})
          </summary>
          <ul className="border-line divide-line max-h-96 divide-y overflow-y-auto border-t text-xs">
            {direct.map((d) => (
              <li key={`${d.ecosystem}:${d.name}:${d.version}`} className="flex items-center justify-between gap-2 px-3 py-1.5">
                <span className="truncate">{d.name}{d.isDev && <span className="text-muted-foreground"> · dev</span>}</span>
                <span className="text-muted-foreground shrink-0">
                  {d.ecosystem} · {d.version ? `${d.versionKind === "Declared" ? "≥ " : ""}${d.version}` : "version unknown"}
                </span>
              </li>
            ))}
          </ul>
        </details>
      </section>

      <ProjectActions id={summary.id} name={summary.name} />
    </div>
  )
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="border-line rounded-md border px-3 py-2">
      <dt className="text-muted-foreground text-[11px]">{label}</dt>
      <dd className="text-lg font-semibold tabular-nums">{value}</dd>
    </div>
  )
}

export default function ProjectPage({ params }: { params: Promise<{ id: string }> }) {
  return (
    <div className="max-w-3xl">
      <Suspense fallback={<Skeleton className="h-64 w-full" />}>
        <Detail params={params} />
      </Suspense>
    </div>
  )
}
