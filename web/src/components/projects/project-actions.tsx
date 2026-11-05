"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { FileDropzone, type DroppedFile } from "@/components/projects/file-dropzone"
import { REQUEST_HEADER, endSession } from "@/lib/auth"
import type { ProjectUploadResult } from "@/lib/api/types"

/** Add or replace files on a project, or delete it. */
export function ProjectActions({ id, name }: { id: string; name: string }) {
  const router = useRouter()
  const [open, setOpen] = useState(false)
  const [files, setFiles] = useState<DroppedFile[]>([])
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null)
  const [confirmDelete, setConfirmDelete] = useState(false)

  async function call(method: string, path: string, body?: unknown): Promise<Response | null> {
    setBusy(true)
    setNotice(null)
    try {
      const res = await fetch(path, {
        method,
        headers: { [REQUEST_HEADER]: "1", ...(body ? { "Content-Type": "application/json" } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      })
      if (res.status === 401) {
        await endSession()
        router.push("/login")
        router.refresh()
        return null
      }
      return res
    } catch {
      setNotice({ kind: "error", text: "Could not reach the server." })
      return null
    } finally {
      setBusy(false)
    }
  }

  async function upload() {
    const res = await call("PUT", `/api/v1/projects/${id}/files`, { files })
    if (!res) return
    if (!res.ok) {
      const body = (await res.json().catch(() => null)) as { error?: { message?: string } } | null
      setNotice({ kind: "error", text: body?.error?.message ?? "Could not update the project." })
      return
    }
    const result = (await res.json()) as ProjectUploadResult
    setFiles([])
    setOpen(false)
    setNotice({
      kind: "ok",
      text: `Updated: ${result.dependencyCount} dependencies.${result.warnings.length ? " " + result.warnings.join(" ") : ""}`,
    })
    router.refresh()
  }

  async function remove() {
    const res = await call("DELETE", `/api/v1/projects/${id}`)
    if (!res) return
    if (!res.ok) {
      setNotice({ kind: "error", text: "Could not delete the project." })
      return
    }
    router.push("/projects")
    router.refresh()
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-2">
        <Button type="button" size="sm" variant="outline" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          {open ? "Cancel" : "Add or replace files"}
        </Button>
        {confirmDelete ? (
          <>
            <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void remove()}
              className="border-severity-critical text-severity-critical hover:bg-severity-critical/10">
              Confirm delete {name}
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={() => setConfirmDelete(false)}>
              Keep
            </Button>
          </>
        ) : (
          <Button type="button" size="sm" variant="outline" onClick={() => setConfirmDelete(true)}>
            Delete
          </Button>
        )}
      </div>

      {open && (
        <div className="border-line flex flex-col gap-3 rounded-md border p-3">
          <p className="text-muted-foreground text-xs">
            Add a lockfile to get exact versions. A file with the same name as an existing one replaces it.
          </p>
          <FileDropzone files={files} onChange={setFiles} />
          <div>
            <Button type="button" size="sm" disabled={busy || files.length === 0} onClick={() => void upload()}>
              {busy ? "Checking…" : "Update project"}
            </Button>
          </div>
        </div>
      )}

      {notice && (
        <p
          role={notice.kind === "error" ? "alert" : "status"}
          className={notice.kind === "error" ? "text-severity-critical text-xs" : "text-xs text-emerald-600"}
        >
          {notice.text}
        </p>
      )}
    </div>
  )
}
