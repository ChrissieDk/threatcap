"use client"

import { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { FileDropzone, type DroppedFile } from "@/components/projects/file-dropzone"
import { REQUEST_HEADER, endSession } from "@/lib/auth"
import type { ProjectUploadResult } from "@/lib/api/types"

export function NewProject({ onDone }: { onDone?: () => void }) {
  const router = useRouter()
  const [name, setName] = useState("")
  const [files, setFiles] = useState<DroppedFile[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [created, setCreated] = useState<ProjectUploadResult | null>(null)

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      const res = await fetch("/api/v1/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json", [REQUEST_HEADER]: "1" },
        body: JSON.stringify({ name, files }),
      })
      if (res.status === 401) {
        await endSession()
        router.push("/login")
        router.refresh()
        return
      }
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: { message?: string } } | null
        setError(body?.error?.message ?? "Could not create the project.")
        return
      }
      const result = (await res.json()) as ProjectUploadResult
      if (result.warnings.length === 0) {
        router.push(`/projects/${result.id}`)
        router.refresh()
        return
      }
      setCreated(result)
    } catch {
      setError("Could not reach the server.")
    } finally {
      setBusy(false)
    }
  }

  if (created) {
    return (
      <div className="border-line flex flex-col gap-2 rounded-md border p-4 text-xs">
        <p className="font-medium">Project created with {created.dependencyCount} dependencies.</p>
        <ul className="text-muted-foreground list-disc pl-4">
          {created.warnings.map((w) => <li key={w}>{w}</li>)}
        </ul>
        <div>
          <Button asChild size="sm">
            <Link href={`/projects/${created.id}`}>Open project</Link>
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="border-line flex flex-col gap-3 rounded-md border p-4">
      <label className="flex flex-col gap-1 text-xs">
        Project name
        <Input value={name} maxLength={80} placeholder="e.g. Billing API" onChange={(e) => setName(e.target.value)} />
      </label>
      <FileDropzone files={files} onChange={setFiles} />
      {error && (
        <p role="alert" className="text-severity-critical text-xs">
          {error}
        </p>
      )}
      <div className="flex gap-2">
        <Button type="button" size="sm" disabled={busy || name.trim() === "" || files.length === 0} onClick={() => void submit()}>
          {busy ? "Checking…" : "Create project"}
        </Button>
        {onDone && (
          <Button type="button" size="sm" variant="outline" onClick={onDone}>
            Cancel
          </Button>
        )}
      </div>
    </div>
  )
}
