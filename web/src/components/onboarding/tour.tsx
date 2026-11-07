"use client"

import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react"
import { CircleHelp } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

const OPEN_EVENT = "threatwatch:tour"
const STORAGE_PREFIX = "threatwatch.tour.v1."

type Step = {
  title: string
  /** CSS selector for the element to spotlight. Skipped when it is not on screen (mobile). */
  target?: string
  body: ReactNode
}

const GLOSSARY: { term: string; meaning: string }[] = [
  { term: "Severity", meaning: "Critical, High, Medium or Low, from the CVSS score." },
  { term: "KEV", meaning: "CISA confirmed it is being exploited in the wild." },
  { term: "EPSS", meaning: "The chance it gets exploited in the next 30 days." },
  { term: "Priority", meaning: "CVSS, EPSS and KEV in one number. Higher goes first." },
]

const STEPS: Step[] = [
  {
    title: "Your week at a glance",
    target: '[aria-label="Summary metrics"]',
    body: "Counts for the technologies you follow over the last 7 days: what is new, what is critical, and what affects your projects.",
  },
  {
    title: "Words you will see",
    body: (
      <dl className="grid gap-1.5">
        {GLOSSARY.map((g) => (
          <div key={g.term} className="grid grid-cols-[4.5rem_1fr] gap-2">
            <dt className="text-foreground font-medium">{g.term}</dt>
            <dd>{g.meaning}</dd>
          </div>
        ))}
      </dl>
    ),
  },
  {
    title: "Projects",
    target: 'aside a[href="/projects"]',
    body: "Drop a package.json or lockfile. You see which advisories hit the exact versions you run, and the version that fixes each one.",
  },
  {
    title: "Follow what you run",
    target: 'aside a[href="/technologies"]',
    body: "Follow technologies and every feed narrows to them: Act now, incidents, the bell and your alerts.",
  },
  {
    title: "Act now",
    target: 'aside a[href="/act-now"]',
    body: "Start here each day. The highest priority issues in your stack, with your project findings. Vulnerabilities and Incidents hold the full lists.",
  },
  {
    title: "Get pinged instead",
    target: '[aria-label="Notifications"]',
    body: "The bell shows what needs attention. In Preferences, add Web Push, ntfy, email or a webhook and we tell you, never twice for the same thing.",
  },
]

function visibleRect(selector?: string): DOMRect | null {
  if (!selector) return null
  const el = document.querySelector(selector)
  if (!el) return null
  const r = el.getBoundingClientRect()
  return r.width > 0 && r.height > 0 ? r : null
}

export function TourButton() {
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label="Take the tour"
      title="Take the tour"
      onClick={() => window.dispatchEvent(new Event(OPEN_EVENT))}
    >
      <CircleHelp aria-hidden />
    </Button>
  )
}

export function OnboardingTour() {
  const [open, setOpen] = useState(false)
  const [step, setStep] = useState(0)
  const [rect, setRect] = useState<DOMRect | null>(null)
  const [size, setSize] = useState({ w: 0, h: 0 })
  const storageKey = useRef<string | null>(null)
  const nextRef = useRef<HTMLButtonElement>(null)
  const cardRef = useRef<HTMLDivElement>(null)

  const finish = useCallback(() => {
    setOpen(false)
    try {
      if (storageKey.current) localStorage.setItem(storageKey.current, "done")
    } catch {
      // Storage can be blocked; the tour then simply shows again next visit.
    }
  }, [])

  // First login: show once per account in this browser.
  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    fetch("/api/v1/auth/me")
      .then(async (res) => {
        if (!res.ok) return
        const body = (await res.json()) as { email?: string }
        storageKey.current = `${STORAGE_PREFIX}${body.email ?? "account"}`
        let seen = false
        try {
          seen = localStorage.getItem(storageKey.current) === "done"
        } catch {
          seen = true
        }
        if (!cancelled && !seen) timer = setTimeout(() => setOpen(true), 700)
      })
      .catch(() => {})
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [])

  useEffect(() => {
    const start = () => {
      setStep(0)
      setOpen(true)
    }
    window.addEventListener(OPEN_EVENT, start)
    return () => window.removeEventListener(OPEN_EVENT, start)
  }, [])

  // Find and follow the spotlighted element.
  useLayoutEffect(() => {
    if (!open) return
    const measure = () => {
      setRect(visibleRect(STEPS[step].target))
      const card = cardRef.current
      if (card) setSize({ w: card.offsetWidth, h: card.offsetHeight })
    }
    const el = STEPS[step].target ? document.querySelector(STEPS[step].target!) : null
    el?.scrollIntoView({ block: "nearest" })
    measure()
    window.addEventListener("resize", measure)
    window.addEventListener("scroll", measure, true)
    return () => {
      window.removeEventListener("resize", measure)
      window.removeEventListener("scroll", measure, true)
    }
  }, [open, step])

  useEffect(() => {
    if (open) nextRef.current?.focus()
  }, [open, step])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") finish()
      else if (e.key === "ArrowRight") setStep((s) => Math.min(s + 1, STEPS.length - 1))
      else if (e.key === "ArrowLeft") setStep((s) => Math.max(s - 1, 0))
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [open, finish])

  if (!open) return null

  const current = STEPS[step]
  const last = step === STEPS.length - 1
  const pad = 4

  // Place the card beside a sidebar target, under a header target, or centred with none.
  let style: React.CSSProperties | undefined
  if (rect && typeof window !== "undefined") {
    const margin = 12
    const w = size.w || 340
    const h = size.h || 220
    const sidebar = rect.right < 360
    const left = sidebar
      ? rect.right + 16
      : Math.min(Math.max(rect.left, margin), window.innerWidth - w - margin)
    const top = sidebar
      ? Math.min(Math.max(rect.top - 8, margin), window.innerHeight - h - margin)
      : Math.min(rect.bottom + 14, window.innerHeight - h - margin)
    style = { left, top }
  }

  return (
    <div className="fixed inset-0 z-100">
      <div className="absolute inset-0" aria-hidden onClick={(e) => e.stopPropagation()} />
      {rect ? (
        <div
          aria-hidden
          className="border-primary pointer-events-none fixed rounded-md border-2 shadow-[0_0_0_9999px_rgba(0,0,0,0.62)] transition-[top,left,width,height] duration-200 motion-reduce:transition-none"
          style={{
            top: rect.top - pad,
            left: rect.left - pad,
            width: rect.width + pad * 2,
            height: rect.height + pad * 2,
          }}
        />
      ) : (
        <div className="absolute inset-0 bg-black/60" aria-hidden />
      )}

      <div
        ref={cardRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="tour-title"
        className={cn(
          "bg-surface border-line-strong fixed w-[min(92vw,22rem)] rounded-lg border p-4 shadow-2xl",
          !style && "top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"
        )}
        style={style}
      >
        <div className="mb-3 flex gap-1" aria-hidden>
          {STEPS.map((s, i) => (
            <span
              key={s.title}
              className={cn("h-0.5 flex-1 rounded-full", i <= step ? "bg-primary" : "bg-line-strong")}
            />
          ))}
        </div>
        <p className="text-muted-foreground text-xs">
          {step + 1} of {STEPS.length}
        </p>
        <h2 id="tour-title" className="mt-1 text-base font-semibold tracking-tight">
          {current.title}
        </h2>
        <div className="text-muted-foreground mt-2 text-[13px] leading-relaxed">{current.body}</div>

        <div className="mt-4 flex items-center justify-between gap-2">
          <Button variant="ghost" size="sm" onClick={finish}>
            Skip tour
          </Button>
          <div className="flex gap-2">
            {step > 0 && (
              <Button variant="outline" size="sm" onClick={() => setStep(step - 1)}>
                Back
              </Button>
            )}
            <Button
              ref={nextRef}
              size="sm"
              onClick={() => (last ? finish() : setStep(step + 1))}
            >
              {last ? "Done" : "Next"}
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
