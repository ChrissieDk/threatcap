import Link from "next/link"
import { Flame } from "lucide-react"
import { SeverityBadge } from "@/components/severity-badge"
import type { ProjectOverview } from "@/lib/api/types"

/** Vulnerabilities that affect the exact versions in the user's projects. */
export function ProjectRisk({ overview, compact = false }: { overview: ProjectOverview; compact?: boolean }) {
  if (overview.projectCount === 0) {
    return (
      <section aria-label="Your projects" className="border-line bg-surface rounded-md border p-4 text-xs">
        <h2 className="text-sm font-medium">See what affects your exact versions</h2>
        <p className="text-muted-foreground mt-1">
          Drop in a package.json, lockfile, .csproj or SBOM and Peregrinet lists the known vulnerabilities in the
          versions you actually run.{" "}
          <Link href="/projects" className="text-primary font-medium underline-offset-2 hover:underline">
            Add a project
          </Link>
        </p>
      </section>
    )
  }

  return (
    <section aria-label="Affecting your projects" className="border-line bg-surface rounded-md border p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-sm font-medium">Affecting your projects</h2>
        <Link href="/projects" className="text-primary text-[11px] underline-offset-2 hover:underline">
          {overview.projectCount} {overview.projectCount === 1 ? "project" : "projects"}
        </Link>
      </div>

      {overview.findingCount === 0 ? (
        <p className="text-muted-foreground mt-2 text-xs">
          None of the versions we could check in your projects have a known vulnerability. New advisories are checked automatically.
        </p>
      ) : (
        <>
          <p className="text-muted-foreground mt-0.5 text-xs">
            {overview.findingCount} known {overview.findingCount === 1 ? "vulnerability" : "vulnerabilities"} across{" "}
            {overview.projectsAffected} {overview.projectsAffected === 1 ? "project" : "projects"}
            {overview.knownExploitedCount > 0 ? ` · ${overview.knownExploitedCount} actively exploited` : ""}.
          </p>
          <ul className={`divide-line mt-3 divide-y ${compact ? "" : "border-line rounded-md border"}`}>
            {overview.top.map((t) => (
              <li key={`${t.projectId}:${t.finding.vulnerabilityId}`} className="flex items-start gap-3 py-2">
                <SeverityBadge severity={t.finding.severity} className="mt-0.5" />
                <div className="min-w-0 flex-1">
                  <Link href={`/vulnerabilities/${t.finding.vulnerabilityId}`} className="hover:text-primary text-[13px] font-medium">
                    {t.finding.canonicalId}
                  </Link>
                  <p className="text-muted-foreground truncate text-[11px]">{t.finding.title}</p>
                  <p className="mt-0.5 text-[11px]">
                    <Link href={`/projects/${t.projectId}`} className="text-primary underline-offset-2 hover:underline">
                      {t.projectName}
                    </Link>
                    {" · "}
                    <code className="bg-background rounded px-1">{t.finding.package}</code>{" "}
                    {t.finding.versionKind === "Declared" ? "≥ " : ""}
                    {t.finding.version}
                    {t.finding.fixedIn && <span className="text-emerald-600"> → upgrade to {t.finding.fixedIn}</span>}
                  </p>
                </div>
                {t.finding.isKnownExploited && (
                  <Flame className="text-severity-high size-3.5 shrink-0" aria-label="Actively exploited" />
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  )
}
