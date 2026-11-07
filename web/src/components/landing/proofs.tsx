import type { ReactNode } from "react"

export type Severity = "critical" | "high" | "unknown"

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  unknown: "Unknown",
}

export function Sev({ level }: { level: Severity }) {
  return <span className={`lp-sev lp-sev--${level}`}>{SEVERITY_LABEL[level]}</span>
}

/** A panel built from the product's own rows. Decorative: the section's text carries the meaning. */
export function Panel({
  label,
  className = "",
  children,
}: {
  label: string
  className?: string
  children: ReactNode
}) {
  return (
    <figure className={`lp-proof lp-ui ${className}`} role="img" aria-label={label}>
      <div aria-hidden="true">{children}</div>
    </figure>
  )
}

const HERO_ROWS = [
  {
    id: "CVE-2026-44494",
    title: "axios Vulnerable to Full Man-in-the-Middle via Prototype Pollution…",
    pkg: "axios",
    have: "1.12.1",
    fix: "1.16.0",
  },
  {
    id: "CVE-2026-39364",
    title: "Vite: `server.fs.deny` bypassed with queries",
    pkg: "vite",
    have: "7.1.2",
    fix: "7.3.2",
  },
  {
    id: "CVE-2026-44488",
    title: "Allocation of Resources Without Limits or Throttling in Axios",
    pkg: "axios",
    have: "1.12.1",
    fix: "1.16.0",
  },
  {
    id: "CVE-2026-45623",
    title: "PostCSS: Arbitrary file read and information disclosure via…",
    pkg: "postcss",
    have: "8.5.6",
    fix: "8.5.12",
  },
]

export function HeroProof() {
  return (
    <Panel
      className="lp-hero-ui"
      label="Threatwatch listing four high-severity advisories that hit a project, each with the installed version struck through and the version that fixes it"
    >
      <div className="lp-ui__head">
        <h3>Affecting your projects</h3>
        <p>19 known vulnerabilities across 1 project.</p>
      </div>
      <ul className="lp-ui__rows">
        {HERO_ROWS.map((row, i) => (
          <li key={row.id} className="lp-hit lp-rise" style={{ ["--i" as string]: i }}>
            <Sev level="high" />
            <div className="lp-hit__body">
              <span className="lp-hit__id lp-measured">{row.id}</span>
              <span className="lp-hit__title">{row.title}</span>
              <span className="lp-hit__fix lp-measured">
                <span className="lp-hit__pkg">{row.pkg}</span>{" "}
                <s className="lp-old">{row.have}</s>{" "}
                <strong className="lp-new">{row.fix}</strong>
              </span>
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

const TABLE_ROWS: { id: string; title: string; level: Severity; cvss: string }[] = [
  { id: "CVE-2026-105769", title: "kaniko can send the build’s Azure…", level: "critical", cvss: "9.3" },
  { id: "CVE-2026-12411", title: "lxd allows Cross-guest volume hijack", level: "high", cvss: "8.4" },
]

export function TableRows() {
  return (
    <div className="lp-mini" role="img" aria-label="Rows from the vulnerability explorer with id, title, severity and CVSS">
      <table className="lp-table" aria-hidden="true">
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Title</th>
            <th scope="col">Severity</th>
            <th scope="col">CVSS</th>
          </tr>
        </thead>
        <tbody>
          {TABLE_ROWS.map((row) => (
            <tr key={row.id}>
              <td className="lp-measured">{row.id}</td>
              <td>{row.title}</td>
              <td><Sev level={row.level} /></td>
              <td className="lp-measured">{row.cvss}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const INCIDENTS = [
  { vendor: "npm", title: "View package and auth outage" },
  { vendor: "Docker", title: "Degraded performance on Docker Hub" },
]

/** A slow vertical ticker of real, resolved incidents. */
export function IncidentTicker() {
  return (
    <div className="lp-ticker" role="img" aria-label="Recently resolved incidents: npm and Docker Hub outages">
      <div className="lp-ticker__track" aria-hidden="true">
        {[0].map((pass) => (
          <ul key={pass} className="lp-ticker__pass">
            {INCIDENTS.map((incident) => (
              <li key={incident.title} className="lp-ticker__item">
                <span className="lp-chip lp-measured">{incident.vendor}</span>
                <span>{incident.title}</span>
              </li>
            ))}
          </ul>
        ))}
      </div>
    </div>
  )
}

/** The commands from the deploy docs, typed once as the tile scrolls into view. */
export function Terminal() {
  return (
    <pre className="lp-term" tabIndex={0} aria-label="Commands to start Threatwatch" data-reveal="type">
      <code>
        <span className="lp-term__line" style={{ ["--i" as string]: 0 }}>cp .env.production.example .env</span>
        <span className="lp-term__line" style={{ ["--i" as string]: 1 }}>chmod 600 .env</span>
        <span className="lp-term__line" style={{ ["--i" as string]: 2 }}>docker compose -f docker-compose.prod.yml up -d --build</span>
      </code>
    </pre>
  )
}
