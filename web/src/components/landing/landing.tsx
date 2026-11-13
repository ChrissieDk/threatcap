import Link from "next/link"
import { Radar } from "lucide-react"
import "./landing.css"
import { FollowTile, MotionRoot, ScrollBar, Story, TryIt } from "./motion"
import { HeroProof, IncidentTicker, TableRows, Terminal } from "./proofs"
import type { PublicStats } from "@/lib/api/public-stats"

export function Landing({ stats }: { stats?: PublicStats | null }) {
  return (
    <MotionRoot>
      <header className="lp-nav">
        <div className="lp-container lp-nav__bar">
          <Link href="/" className="lp-brand" aria-label="Threatwatch home">
            <Radar size={22} aria-hidden />
            <span>Threatwatch</span>
          </Link>
          <nav className="lp-nav__links" aria-label="Page sections">
            <a href="#how">How it works</a>
            <a href="#try">Try it</a>
            <a href="#toolbox">Toolbox</a>
            <a href="#self-host">Self-host</a>
          </nav>
          <div className="lp-nav__cta">
            <Link href="/login" className="lp-btn lp-btn--sm">Sign in</Link>
            <Link href="/register" className="lp-btn lp-btn--sm lp-btn--primary">Create account</Link>
          </div>
        </div>
        <ScrollBar />
      </header>

      <main>
        <section className="lp-hero">
          <div className="lp-container lp-hero__grid">
            <div className="lp-hero__text">
              <h1>Stop finding CVEs on Twitter.</h1>
              <p className="lp-lead">
                Threatwatch ranks every advisory against the packages you actually run.
              </p>
              <div className="lp-actions">
                <Link href="/register" className="lp-btn lp-btn--primary">Create account</Link>
                <Link href="/login" className="lp-btn">Sign in</Link>
              </div>
              <p className="lp-terms">Free to run. Your lockfile is read, never stored.</p>
              {stats && stats.vulnerabilitiesPickedUp > 0 && (
                <p className="lp-pickup">
                  <strong className="lp-measured">{stats.vulnerabilitiesPickedUp.toLocaleString("en-GB")}</strong>{" "}
                  vulnerabilities picked up so far
                </p>
              )}
            </div>
            <HeroProof />
          </div>
        </section>

        <Story />

        <section className="lp-try" id="try">
          <div className="lp-container lp-try__grid">
            <div className="lp-try__text" data-reveal>
              <h2>Take it for a spin.</h2>
              <p className="lp-lead">A sample file, three real advisories. Your own files are one account away.</p>
              <Link href="/register" className="lp-btn">Check your own</Link>
            </div>
            <TryIt />
          </div>
        </section>

        <section className="lp-toolbox" id="toolbox">
          <div className="lp-container">
            <h2 data-reveal>The rest of the toolbox.</h2>
            <div className="lp-bento">
              <article className="lp-tile lp-tile--wide" data-reveal style={{ ["--i" as string]: 0 }}>
                <h3>Every advisory, one table.</h3>
                <TableRows />
              </article>

              <article className="lp-tile" data-reveal style={{ ["--i" as string]: 1 }}>
                <h3>Know when npm is down.</h3>
                <p>GitHub, npm, PyPI, Cloudflare, Docker.</p>
                <IncidentTicker />
              </article>

              <article className="lp-tile" data-reveal style={{ ["--i" as string]: 2 }}>
                <h3>Follow what you run.</h3>
                <FollowTile />
              </article>

              <article className="lp-tile lp-tile--wide lp-tile--code" id="self-host" data-reveal style={{ ["--i" as string]: 3 }}>
                <h3>Run it yourself.</h3>
                <p>No paid services.</p>
                <Terminal />
              </article>
            </div>
          </div>
        </section>

        <section className="lp-close">
          <div className="lp-container lp-close__grid">
            <h2 data-reveal>Find out what is in your lockfile.</h2>
            <div className="lp-actions" data-reveal style={{ ["--i" as string]: 1 }}>
              <Link href="/register" className="lp-btn lp-btn--primary">Create account</Link>
              <Link href="/login" className="lp-btn">Sign in</Link>
            </div>
          </div>
        </section>
      </main>

      <footer className="lp-footer">
        <div className="lp-container">
          <p>
            Advisories from OSV.dev, CISA KEV and FIRST EPSS. Incidents from public status pages.{" "}
            <Link href="/login" className="lp-link">Sign in</Link> or{" "}
            <Link href="/register" className="lp-link">create an account</Link>.
          </p>
        </div>
      </footer>
    </MotionRoot>
  )
}
