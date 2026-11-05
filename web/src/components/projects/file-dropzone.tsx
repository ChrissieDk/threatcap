"use client"

import { useRef, useState } from "react"
import { ClipboardPaste, FileUp, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { PASTE_FILE_TYPES, detectFileName } from "@/lib/project-files"

export type DroppedFile = { name: string; content: string }

const MAX_FILES = 10
const MAX_FILE_BYTES = 5_000_000
const ACCEPT =
  ".json,.lock,.yaml,.yml,.txt,.csproj,.fsproj,.vbproj,.props,.targets,.config,.mod,.toml,.xml"

/** Drop or choose dependency files; contents are read in the browser and parsed by the server. */
export function FileDropzone({
  files,
  onChange,
}: {
  files: DroppedFile[]
  onChange: (files: DroppedFile[]) => void
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pasting, setPasting] = useState(false)
  const [pasted, setPasted] = useState("")
  const [pastedType, setPastedType] = useState("auto")

  function addPasted() {
    const content = pasted.trim()
    if (!content) return
    if (content.length > MAX_FILE_BYTES) {
      setError("Pasted text is larger than 5 MB.")
      return
    }
    const name = pastedType === "auto" ? detectFileName(content) : pastedType
    const next = files.filter((f) => f.name.toLowerCase() !== name.toLowerCase())
    if (next.length >= MAX_FILES) {
      setError(`You can add at most ${MAX_FILES} files.`)
      return
    }
    onChange([...next, { name, content }])
    setPasted("")
    setPasting(false)
    setError(null)
  }

  async function add(list: FileList | File[]) {
    setError(null)
    const incoming = Array.from(list)
    const next = [...files]
    for (const file of incoming) {
      if (file.size > MAX_FILE_BYTES) {
        setError(`${file.name} is larger than ${MAX_FILE_BYTES / 1_000_000} MB.`)
        continue
      }
      if (next.length >= MAX_FILES) {
        setError(`You can add at most ${MAX_FILES} files.`)
        break
      }
      const content = await file.text()
      const existing = next.findIndex((f) => f.name.toLowerCase() === file.name.toLowerCase())
      if (existing >= 0) next[existing] = { name: file.name, content }
      else next.push({ name: file.name, content })
    }
    onChange(next)
  }

  return (
    <div className="flex flex-col gap-2">
      <div
        role="button"
        tabIndex={0}
        aria-label="Drop dependency files here or press Enter to choose files"
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault()
            inputRef.current?.click()
          }
        }}
        onDragOver={(e) => {
          e.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragging(false)
          void add(e.dataTransfer.files)
        }}
        className={`flex cursor-pointer flex-col items-center gap-1.5 rounded-md border border-dashed px-4 py-8 text-center text-xs transition-colors focus-visible:ring-primary/40 focus-visible:ring-[3px] focus-visible:outline-none ${
          dragging ? "border-primary bg-primary/5" : "border-line-strong hover:border-primary/60"
        }`}
      >
        <FileUp className="text-muted-foreground size-5" aria-hidden />
        <p className="font-medium">Drop your dependency files here</p>
        <p className="text-muted-foreground max-w-md">
          package.json, package-lock.json, pnpm-lock.yaml, yarn.lock, requirements.txt, poetry.lock, Pipfile.lock,
          *.csproj, go.mod, Cargo.toml / Cargo.lock, pom.xml or a CycloneDX / SPDX SBOM. Add a lockfile for exact versions.
        </p>
        <input
          ref={inputRef}
          type="file"
          multiple
          accept={ACCEPT}
          className="sr-only"
          tabIndex={-1}
          onChange={(e) => {
            if (e.target.files) void add(e.target.files)
            e.target.value = ""
          }}
        />
      </div>

      <button
        type="button"
        className="text-primary flex w-fit items-center gap-1 text-xs underline-offset-2 hover:underline"
        aria-expanded={pasting}
        onClick={() => setPasting((v) => !v)}
      >
        <ClipboardPaste className="size-3.5" aria-hidden />
        {pasting ? "Hide paste box" : "Or paste the file contents"}
      </button>

      {pasting && (
        <div className="border-line flex flex-col gap-2 rounded-md border p-3">
          <label className="flex flex-col gap-1 text-xs">
            File type
            <select
              value={pastedType}
              onChange={(e) => setPastedType(e.target.value)}
              className="border-line-strong bg-surface focus-visible:border-primary focus-visible:ring-primary/30 h-8 w-fit rounded-md border px-2 text-xs outline-none focus-visible:ring-[3px]"
            >
              <option value="auto">Detect automatically</option>
              {PASTE_FILE_TYPES.map((t) => (
                <option key={t.name} value={t.name}>{t.label}</option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Contents
            <textarea
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              rows={8}
              spellCheck={false}
              placeholder={'{\n  "dependencies": {\n    "lodash": "^4.17.0"\n  }\n}'}
              className="border-line-strong bg-surface focus-visible:border-primary focus-visible:ring-primary/30 rounded-md border px-2.5 py-2 font-mono text-xs outline-none focus-visible:ring-[3px]"
            />
          </label>
          <div>
            <Button type="button" size="sm" disabled={pasted.trim() === ""} onClick={addPasted}>
              Add pasted file
            </Button>
          </div>
        </div>
      )}

      {error && (
        <p role="alert" className="text-severity-critical text-xs">
          {error}
        </p>
      )}

      {files.length > 0 && (
        <ul className="flex flex-wrap gap-1.5">
          {files.map((f) => (
            <li key={f.name} className="border-line bg-surface flex items-center gap-1 rounded-md border py-0.5 pr-1 pl-2 text-xs">
              {f.name}
              <button
                type="button"
                aria-label={`Remove ${f.name}`}
                className="text-muted-foreground hover:text-foreground rounded p-0.5"
                onClick={() => onChange(files.filter((x) => x.name !== f.name))}
              >
                <X className="size-3" aria-hidden />
              </button>
            </li>
          ))}
        </ul>
      )}
      <p className="text-muted-foreground text-[11px]">
        Files are read by the server to list your dependencies and are not stored.
      </p>
    </div>
  )
}
