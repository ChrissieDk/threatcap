import { Suspense } from "react"
import { redirect } from "next/navigation"
import { connection } from "next/server"
import { ApiError, apiGet } from "@/lib/api/client"
import type { ProjectSummary } from "@/lib/api/types"
import { EmptyState } from "@/components/empty-state"
import { NewProject } from "@/components/projects/new-project"
import { ProjectsList } from "@/components/projects/projects-list"
import { Skeleton } from "@/components/ui/skeleton"

export const metadata = { title: "Projects" }

async function Projects() {
  await connection()
  let projects: ProjectSummary[]
  try {
    projects = await apiGet<ProjectSummary[]>("/api/v1/projects")
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) redirect("/login")
    return (
      <EmptyState
        title="Could not load your projects"
        description="The API may be unavailable, or it may be missing the latest database update. You can still add a project above."
      />
    )
  }
  return <ProjectsList projects={projects} />
}

export default function ProjectsPage() {
  return (
    <div className="flex max-w-3xl flex-col gap-4">
      <div>
        <h1 className="text-base font-semibold">Projects</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          Drop in a package.json, lockfile, requirements.txt, .csproj, go.mod, pom.xml or SBOM to see which known
          vulnerabilities affect the exact versions you use, and get alerted when new ones appear.
        </p>
      </div>
      <section aria-labelledby="new-project-heading" className="flex flex-col gap-2">
        <h2 id="new-project-heading" className="text-sm font-semibold">Add a project</h2>
        <NewProject />
      </section>
      <h2 className="text-sm font-semibold">Your projects</h2>
      <Suspense fallback={<Skeleton className="h-24 w-full" />}>
        <Projects />
      </Suspense>
    </div>
  )
}
