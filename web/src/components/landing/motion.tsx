"use client"

import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react"
import { Sev } from "./proofs"

/**
 * Adds `js` once scripting is live, then marks every [data-reveal] element `is-in` as it
 * scrolls into view. Elements already on screen are marked in the same layout pass, so nothing
 * flickers. Without scripting the class never lands and everything stays visible.
 */
export function MotionRoot({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)

  useLayoutEffect(() => {
    const root = ref.current
    if (!root) return
    root.classList.add("js")
    const targets = Array.from(root.querySelectorAll<HTMLElement>("[data-reveal]"))
    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-in")
            io.unobserve(entry.target)
          }
        }
      },
      { rootMargin: "0px 0px -12% 0px", threshold: 0.15 }
    )
    for (const el of targets) {
      const r = el.getBoundingClientRect()
      if (r.top < window.innerHeight * 0.9 && r.bottom > 0) el.classList.add("is-in")
      else io.observe(el)
    }
    return () => io.disconnect()
  }, [])

  return (
    <div className="lp" ref={ref}>
      {children}
    </div>
  )
}

/** A thin bar that fills as the page scrolls; transform only. */
export function ScrollBar() {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const bar = ref.current
    if (!bar) return
    let frame = 0
    const update = () => {
      frame = 0
      const max = document.documentElement.scrollHeight - window.innerHeight
      const p = max > 0 ? Math.min(1, window.scrollY / max) : 0
      bar.style.transform = `scaleX(${p})`
    }
    const onScroll = () => {
      if (!frame) frame = requestAnimationFrame(update)
    }
    update()
    window.addEventListener("scroll", onScroll, { passive: true })
    return () => {
      window.removeEventListener("scroll", onScroll)
      if (frame) cancelAnimationFrame(frame)
    }
  }, [])
  return <div className="lp-progress" ref={ref} aria-hidden="true" />
}

const STEPS = [
  { title: "Drop a lockfile.", line: "Or go.mod, pom.xml, an SBOM. Read, never stored." },
  { title: "Matched to exact versions.", line: "Axios 1.12.1 is hit. Axios 1.16.0 is not." },
  { title: "Ranked by what gets exploited.", line: "CVSS, EPSS and CISA’s exploited list set the order." },
  { title: "Pinged where you already are.", line: "Push, ntfy, email or webhook. Never twice." },
]

const DEPS = [
  { pkg: "axios", have: "1.12.1", fix: "1.16.0", count: 2 },
  { pkg: "vite", have: "7.1.2", fix: "7.3.2", count: 1 },
  { pkg: "postcss", have: "8.5.6", fix: "8.5.18", count: 2 },
]

// `from` is the order advisories arrive in; `to` is the order their priority puts them in.
const RANKED = [
  { score: "9.9", id: "CVE-2026-44266", title: "Elo Ruby backend has Remote Cod…", level: "critical" as const, from: 3, to: 0 },
  { score: "9.9", id: "CVE-2026-44267", title: "Elo JavaScript emitter has sandbox…", level: "critical" as const, from: 2, to: 1 },
  { score: "8.2", id: "RUSTSEC-2026-0434", title: "`ant-releases`: extracting a rele…", level: "high" as const, from: 0, to: 2 },
  { score: "8.1", id: "CVE-2026-11800", title: "Keycloak has authentication bypas…", level: "high" as const, from: 1, to: 3 },
]

const TOASTS = [
  { channel: "Web Push", text: "High: axios 1.12.1 in Test. Upgrade to 1.16.0." },
  { channel: "ntfy", text: "Critical: CVE-2026-44266 in your stack." },
  { channel: "Email", text: "Daily digest: 19 advisories for Test." },
  { channel: "Webhook", text: "POST sent with CVE-2026-44494." },
]

/** The pinned story: text steps scroll on the left, one panel on the right changes with them. */
export function Story() {
  const [step, setStep] = useState(0)
  const refs = useRef<(HTMLLIElement | null)[]>([])

  useEffect(() => {
    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) setStep(Number((entry.target as HTMLElement).dataset.step))
        }
      },
      { rootMargin: "-45% 0px -45% 0px" }
    )
    for (const el of refs.current) if (el) io.observe(el)
    return () => io.disconnect()
  }, [])

  return (
    <section className="lp-story" id="how">
      <div className="lp-container">
        <h2 className="lp-story__head" data-reveal>From lockfile to alert.</h2>
        <div className="lp-story__grid">
          <ol className="lp-steps">
            {STEPS.map((s, i) => (
              <li
                key={s.title}
                className="lp-step"
                data-step={i}
                data-current={step === i}
                ref={(el) => {
                  refs.current[i] = el
                }}
              >
                <h3>{s.title}</h3>
                <p>{s.line}</p>
              </li>
            ))}
          </ol>

          <div className="lp-stage" data-step={step} role="img" aria-label="Product panel that changes with each step: a drop zone, matched dependencies, ranked advisories and alert notifications">
            <div className="lp-state lp-state--drop" aria-hidden="true">
              <div className="lp-drop lp-drop--big">
                <p className="lp-drop__title">Drop your dependency files here</p>
                <ul className="lp-files lp-measured">
                  <li style={{ ["--i" as string]: 0 }}>package.json</li>
                  <li style={{ ["--i" as string]: 1 }}>pnpm-lock.yaml</li>
                  <li style={{ ["--i" as string]: 2 }}>go.mod</li>
                </ul>
              </div>
            </div>

            <div className="lp-state lp-state--deps" aria-hidden="true">
              <p className="lp-state__title">Test, 40 dependencies</p>
              <ul className="lp-deps">
                {DEPS.map((d, i) => (
                  <li key={d.pkg} style={{ ["--i" as string]: i }}>
                    <span className="lp-measured lp-deps__pkg">{d.pkg}</span>
                    <span className="lp-measured">
                      <s className="lp-old">{d.have}</s> <strong className="lp-new">{d.fix}</strong>
                    </span>
                    <span className="lp-chip lp-chip--high">{d.count} {d.count === 1 ? "advisory" : "advisories"}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="lp-state lp-state--rank" aria-hidden="true">
              <ul className="lp-rankstack">
                {RANKED.map((r) => (
                  <li
                    key={r.id}
                    className="lp-rankrow"
                    style={{ ["--from" as string]: r.from, ["--to" as string]: r.to }}
                  >
                    <span className="lp-rank__score lp-measured">{r.score}</span>
                    <span className="lp-rankrow__body">
                      <span className="lp-hit__title">{r.title}</span>
                      <span className="lp-measured lp-rank__id">{r.id}</span>
                    </span>
                    <Sev level={r.level} />
                  </li>
                ))}
              </ul>
            </div>

            <div className="lp-state lp-state--alert" aria-hidden="true">
              <ul className="lp-toasts">
                {TOASTS.map((t, i) => (
                  <li key={t.channel} style={{ ["--i" as string]: i }}>
                    <span className="lp-toast__channel">{t.channel}</span>
                    <span>{t.text}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

type Row = { eco: string; id: string; title: string; level: "critical" | "high" | "unknown" }

const ECOSYSTEMS = ["npm", "Go"]

const FOLLOW_ROWS: Row[] = [
  { eco: "Go", id: "CVE-2026-105769", title: "kaniko can send the build’s Azure…", level: "critical" },
  { eco: "npm", id: "CVE-2026-44494", title: "axios Vulnerable to Full…", level: "high" },
]

/** Follow toggles that narrow the feed beneath them, the way every feed in the app narrows. */
export function FollowTile() {
  const [on, setOn] = useState<Set<string>>(() => new Set(ECOSYSTEMS))

  function toggle(eco: string) {
    setOn((prev) => {
      const next = new Set(prev)
      if (next.has(eco)) next.delete(eco)
      else next.add(eco)
      return next
    })
  }

  return (
    <div className="lp-follow">
      <ul className="lp-toggles" aria-label="Technologies you follow">
        {ECOSYSTEMS.map((eco) => (
          <li key={eco}>
            <button
              type="button"
              className="lp-toggle"
              aria-pressed={on.has(eco)}
              onClick={() => toggle(eco)}
            >
              {eco}
            </button>
          </li>
        ))}
      </ul>
      <ul className="lp-feed" aria-live="polite">
        {FOLLOW_ROWS.map((row) => (
          <li key={row.id} className="lp-feed__row" data-on={on.has(row.eco)}>
            <Sev level={row.level} />
            <span className="lp-feed__body">
              <span className="lp-hit__title">{row.title}</span>
              <span className="lp-measured lp-rank__id">{row.id}</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

type Rule = { pkg: string; from: string; fix: string; ids: string[] }

// Real advisories from the Threatwatch instance this page was built from: affected from `from` up to, not including, `fix`.
const RULES: Rule[] = [
  { pkg: "axios", from: "1.12.1", fix: "1.16.0", ids: ["CVE-2026-44494", "CVE-2026-44488"] },
  { pkg: "vite", from: "7.1.2", fix: "7.3.2", ids: ["CVE-2026-39364"] },
  { pkg: "postcss", from: "8.5.6", fix: "8.5.18", ids: ["CVE-2026-45623", "CVE-2026-73646"] },
]

const SAMPLE_DEPS: { pkg: string; range: string }[] = [
  { pkg: "axios", range: "^1.12.1" },
  { pkg: "postcss", range: "8.5.6" },
  { pkg: "react", range: "^19.0.0" },
  { pkg: "vite", range: "~7.1.2" },
]

function parseVersion(range: string): number[] | null {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(range)
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null
}

function compare(a: number[], b: number[]): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i]
  return 0
}

/** The advisory a sample dependency hits, if any: affected from `from` up to, not including, `fix`. */
function match(pkg: string, range: string): { rule: Rule; have: string } | null {
  const rule = RULES.find((r) => r.pkg === pkg)
  const have = parseVersion(range)
  if (!rule || !have) return null
  const inRange = compare(have, parseVersion(rule.from)!) >= 0 && compare(have, parseVersion(rule.fix)!) < 0
  return inRange ? { rule, have: have.join(".") } : null
}

/** A scripted run on a sample package.json: nothing is uploaded, so the real thing stays behind sign-up. */
export function TryIt() {
  const [checked, setChecked] = useState(0)
  const [running, setRunning] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current)
  }, [])

  function run() {
    if (running) return
    const instant = window.matchMedia("(prefers-reduced-motion: reduce)").matches
    setChecked(0)
    if (instant) {
      setChecked(SAMPLE_DEPS.length)
      return
    }
    setRunning(true)
    let n = 0
    const step = () => {
      n += 1
      setChecked(n)
      if (n < SAMPLE_DEPS.length) timer.current = setTimeout(step, 650)
      else setRunning(false)
    }
    timer.current = setTimeout(step, 500)
  }

  const done = checked >= SAMPLE_DEPS.length

  return (
    <div className="lp-try__panel lp-proof">
      <div className="lp-try__row">
        <p className="lp-state__title lp-measured">package.json</p>
        <button type="button" className="lp-btn lp-btn--primary" onClick={run} disabled={running}>
          {running ? "Checking" : done ? "Run again" : "Run the check"}
        </button>
      </div>
      <ul className="lp-scan" aria-live="polite">
        {SAMPLE_DEPS.map((d, i) => {
          const hit = match(d.pkg, d.range)
          const shown = i < checked
          const scanning = running && i === checked
          return (
            <li key={d.pkg} className="lp-scan__row" data-scanning={scanning} data-shown={shown}>
              <span className="lp-measured lp-scan__pkg">{d.pkg}</span>
              <span className="lp-measured lp-scan__range">{d.range}</span>
              <span className="lp-scan__result">
                {shown && hit && (
                  <>
                    <Sev level="high" />
                    <span className="lp-measured">
                      <s className="lp-old">{hit.have}</s> <strong className="lp-new">{hit.rule.fix}</strong>
                    </span>
                  </>
                )}
                {shown && !hit && <span className="lp-scan__clear">No match</span>}
              </span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
