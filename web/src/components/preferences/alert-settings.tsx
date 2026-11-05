"use client"

import { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Bell, Mail, Smartphone, Webhook } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { RelativeTime } from "@/components/relative-time"
import { NtfySetupPanel } from "@/components/preferences/ntfy-setup"
import { REQUEST_HEADER, endSession } from "@/lib/auth"
import { describeBrowser, pushSupported, subscribeToPush } from "@/lib/push"
import type {
  AlertChannel,
  AlertPreference,
  AlertState,
  NtfySetup,
} from "@/lib/api/types"

type Preset = { id: string; title: string; description: string; rules: AlertPreference }

const PRESETS: Preset[] = [
  {
    id: "urgent",
    title: "Only urgent",
    description: "Actively exploited or critical vulnerabilities. Quietest.",
    rules: { minSeverity: "Critical", alwaysAlertKnownExploited: true, minEpss: null, includeIncidents: false, mode: "Instant" },
  },
  {
    id: "balanced",
    title: "Balanced",
    description: "High severity and up, plus anything actively exploited.",
    rules: { minSeverity: "High", alwaysAlertKnownExploited: true, minEpss: null, includeIncidents: false, mode: "Instant" },
  },
  {
    id: "everything",
    title: "Everything",
    description: "All severities and vendor incidents or outages. Noisiest.",
    rules: { minSeverity: "Low", alwaysAlertKnownExploited: true, minEpss: null, includeIncidents: true, mode: "Instant" },
  },
]

const SEVERITIES: AlertPreference["minSeverity"][] = ["Low", "Medium", "High", "Critical"]

const selectClass =
  "border-line-strong bg-surface focus-visible:border-primary focus-visible:ring-primary/30 h-8 rounded-md border px-2 text-xs outline-none focus-visible:ring-[3px]"

function matchPreset(pref: AlertPreference): string {
  const hit = PRESETS.find(
    (p) =>
      p.rules.minSeverity === pref.minSeverity &&
      p.rules.alwaysAlertKnownExploited === pref.alwaysAlertKnownExploited &&
      p.rules.minEpss === pref.minEpss &&
      p.rules.includeIncidents === pref.includeIncidents &&
      p.rules.mode === pref.mode
  )
  return hit?.id ?? "custom"
}

async function api(method: string, path: string, body?: unknown): Promise<Response> {
  return fetch(path, {
    method,
    headers: {
      [REQUEST_HEADER]: "1",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
}

async function errorMessage(res: Response, fallback: string): Promise<string> {
  try {
    const data = (await res.json()) as { error?: { message?: string } }
    return data.error?.message ?? fallback
  } catch {
    return fallback
  }
}

export function AlertSettings({ state, welcome }: { state: AlertState; welcome: boolean }) {
  const router = useRouter()
  const [pref, setPref] = useState<AlertPreference>(state.preference)
  const [epss, setEpss] = useState(state.preference.minEpss === null ? "" : String(state.preference.minEpss * 100))
  const [customize, setCustomize] = useState(matchPreset(state.preference) === "custom")
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [ntfySetup, setNtfySetup] = useState<{ channelId: string | null; setup: NtfySetup } | null>(null)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [hookType, setHookType] = useState<"Webhook" | "Ntfy">("Webhook")
  const [hookLabel, setHookLabel] = useState("")
  const [hookTarget, setHookTarget] = useState("")

  const hasChannels = state.channels.length > 0

  /** Runs a request, handling sign-out, errors and refresh. Returns the response on success. */
  async function run(action: () => Promise<Response>, fallback: string, okText?: string) {
    setBusy(true)
    setNotice(null)
    try {
      const res = await action()
      if (res.status === 401) {
        await endSession()
        router.push("/login")
        router.refresh()
        return null
      }
      if (!res.ok) {
        setNotice({ kind: "error", text: await errorMessage(res, fallback) })
        return null
      }
      if (okText) setNotice({ kind: "ok", text: okText })
      router.refresh()
      return res
    } catch {
      setNotice({ kind: "error", text: "Could not reach the server." })
      return null
    } finally {
      setBusy(false)
    }
  }

  function savePref(next: AlertPreference, okText = "Rules saved.") {
    setPref(next)
    void run(() => api("PUT", "/api/v1/alerts/preferences", next), "Could not save rules.", okText)
  }

  function saveCustom() {
    const trimmed = epss.trim()
    const parsed = trimmed === "" ? null : Number(trimmed) / 100
    if (parsed !== null && (Number.isNaN(parsed) || parsed < 0 || parsed > 1)) {
      setNotice({ kind: "error", text: "EPSS threshold must be a percentage between 0 and 100." })
      return
    }
    savePref({ ...pref, minEpss: parsed })
  }

  async function enableBrowser() {
    if (!state.pushPublicKey) return
    setBusy(true)
    setNotice(null)
    try {
      const sub = await subscribeToPush(state.pushPublicKey)
      const res = await api("POST", "/api/v1/alerts/channels/push", {
        ...sub,
        label: describeBrowser(navigator.userAgent),
      })
      if (!res.ok) {
        setNotice({ kind: "error", text: await errorMessage(res, "Could not enable browser alerts.") })
        return
      }
      setNotice({ kind: "ok", text: "Browser alerts enabled. Press “Send test” to see one." })
      router.refresh()
    } catch (err) {
      setNotice({ kind: "error", text: err instanceof Error ? err.message : "Could not enable browser alerts." })
    } finally {
      setBusy(false)
    }
  }

  async function addPhone() {
    const res = await run(
      () => api("POST", "/api/v1/alerts/channels", { type: "Ntfy", label: "Phone (ntfy)" }),
      "Could not create phone alerts."
    )
    if (!res) return
    const channel = (await res.json()) as AlertChannel
    await showNtfy(channel.id)
  }

  async function showNtfy(channelId: string) {
    try {
      const res = await api("GET", `/api/v1/alerts/channels/${channelId}/setup`)
      if (res.ok) setNtfySetup({ channelId, setup: (await res.json()) as NtfySetup })
    } catch {
      setNotice({ kind: "error", text: "Could not load setup details." })
    }
  }

  async function testChannel(channel: AlertChannel) {
    setBusy(true)
    setNotice(null)
    try {
      const res = await api("POST", `/api/v1/alerts/channels/${channel.id}/test`)
      if (!res.ok) {
        setNotice({ kind: "error", text: await errorMessage(res, "Test failed.") })
        return
      }
      const data = (await res.json()) as { ok: boolean; error: string | null }
      setNotice(
        data.ok
          ? { kind: "ok", text: `Test sent to ${channel.label}.` }
          : { kind: "error", text: `Test failed: ${data.error ?? "unknown error"}` }
      )
      router.refresh()
    } catch {
      setNotice({ kind: "error", text: "Could not reach the server." })
    } finally {
      setBusy(false)
    }
  }

  const activePreset = matchPreset(pref)
  const pushOk = pushSupported() && !!state.pushPublicKey

  return (
    <div className="flex max-w-2xl flex-col gap-6">
      {welcome && !hasChannels && (
        <div className="border-primary/40 bg-primary/5 rounded-md border p-4 text-xs">
          <p className="text-sm font-semibold">Welcome — let’s set up your alerts</p>
          <p className="text-muted-foreground mt-1">
            Three quick steps: pick what you follow, choose how urgent alerts should be, then pick where to
            receive them. It takes about a minute.
          </p>
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

      <section aria-labelledby="step1" className="border-line flex flex-col gap-2 rounded-md border p-4">
        <h2 id="step1" className="text-sm font-semibold">1. What you follow</h2>
        {state.followedCount === 0 ? (
          <p className="text-xs">
            You don’t follow anything yet, so there is nothing to alert on.{" "}
            <Link href="/technologies" className="text-primary font-medium underline-offset-2 hover:underline">
              Follow your languages, frameworks and packages
            </Link>
          </p>
        ) : (
          <p className="text-muted-foreground text-xs">
            You follow {state.followedCount} {state.followedCount === 1 ? "technology" : "technologies"}.{" "}
            <Link href="/technologies" className="text-primary underline-offset-2 hover:underline">
              Manage
            </Link>
          </p>
        )}
      </section>

      <section aria-labelledby="step2" className="border-line flex flex-col gap-3 rounded-md border p-4">
        <h2 id="step2" className="text-sm font-semibold">2. How urgent should alerts be?</h2>
        <div role="radiogroup" aria-labelledby="step2" className="grid gap-2 sm:grid-cols-3">
          {PRESETS.map((p) => (
            <button
              key={p.id}
              type="button"
              role="radio"
              aria-checked={activePreset === p.id}
              disabled={busy}
              onClick={() => {
                setEpss("")
                savePref(p.rules)
              }}
              className={`rounded-md border p-3 text-left text-xs transition-colors ${
                activePreset === p.id ? "border-primary bg-primary/5" : "border-line hover:border-line-strong"
              }`}
            >
              <span className="block font-medium">{p.title}</span>
              <span className="text-muted-foreground mt-1 block">{p.description}</span>
            </button>
          ))}
        </div>
        {activePreset === "custom" && <p className="text-muted-foreground text-xs">Using your custom rules.</p>}

        <button
          type="button"
          className="text-primary w-fit text-xs underline-offset-2 hover:underline"
          aria-expanded={customize}
          onClick={() => setCustomize((v) => !v)}
        >
          {customize ? "Hide custom rules" : "Customize rules"}
        </button>

        {customize && (
          <div className="border-line flex flex-col gap-3 border-t pt-3">
            <label className="flex items-center justify-between gap-4 text-xs">
              Minimum severity
              <select
                className={selectClass}
                value={pref.minSeverity}
                onChange={(e) => setPref({ ...pref, minSeverity: e.target.value as AlertPreference["minSeverity"] })}
              >
                {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </label>
            <label className="flex items-center justify-between gap-4 text-xs">
              Always alert for actively exploited (CISA KEV)
              <input
                type="checkbox"
                checked={pref.alwaysAlertKnownExploited}
                onChange={(e) => setPref({ ...pref, alwaysAlertKnownExploited: e.target.checked })}
              />
            </label>
            <label className="flex items-center justify-between gap-4 text-xs">
              Minimum EPSS exploit probability (%, optional)
              <Input className="w-24" inputMode="decimal" placeholder="any" value={epss} onChange={(e) => setEpss(e.target.value)} />
            </label>
            <label className="flex items-center justify-between gap-4 text-xs">
              Include vendor incidents and outages
              <input
                type="checkbox"
                checked={pref.includeIncidents}
                onChange={(e) => setPref({ ...pref, includeIncidents: e.target.checked })}
              />
            </label>
            <label className="flex items-center justify-between gap-4 text-xs">
              Delivery
              <select
                className={selectClass}
                value={pref.mode}
                onChange={(e) => setPref({ ...pref, mode: e.target.value as AlertPreference["mode"] })}
              >
                <option value="Instant">As it happens</option>
                <option value="DailyDigest">Daily digest</option>
              </select>
            </label>
            <div>
              <Button type="button" size="sm" disabled={busy} onClick={saveCustom}>Save rules</Button>
            </div>
          </div>
        )}
      </section>

      <section aria-labelledby="step3" className="border-line flex flex-col gap-3 rounded-md border p-4">
        <h2 id="step3" className="text-sm font-semibold">3. Where should we send them?</h2>

        <div className="grid gap-2 sm:grid-cols-3">
          <ChannelCard
            icon={<Bell className="size-4" aria-hidden />}
            title="This browser"
            text="Pop-up notifications on this device. No account needed."
            action={
              <Button type="button" size="sm" disabled={busy || !pushOk} onClick={() => void enableBrowser()}>
                Enable
              </Button>
            }
            note={!pushOk ? "Not supported in this browser." : undefined}
          />

          <ChannelCard
            icon={<Mail className="size-4" aria-hidden />}
            title="Email"
            text={state.email ? `Sent to ${state.email}.` : "Sent to your account email."}
            action={
              !state.emailAvailable ? null : state.emailVerified ? (
                <Button
                  type="button"
                  size="sm"
                  disabled={busy}
                  onClick={() =>
                    void run(
                      () => api("POST", "/api/v1/alerts/channels", { type: "Email" }),
                      "Could not enable email alerts.",
                      "Email alerts enabled."
                    )
                  }
                >
                  Email me
                </Button>
              ) : (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() =>
                    void run(
                      () => api("POST", "/api/v1/auth/verify-email/send"),
                      "Could not send the verification email.",
                      "Verification email sent. Open the link in it, then come back and click “Email me”."
                    )
                  }
                >
                  Verify email
                </Button>
              )
            }
            note={
              !state.emailAvailable
                ? "The server admin hasn’t set up email."
                : state.emailVerified
                  ? undefined
                  : "Verify your address first."
            }
          />

          <ChannelCard
            icon={<Smartphone className="size-4" aria-hidden />}
            title="Phone"
            text="Free push notifications via the ntfy app."
            action={
              <Button type="button" size="sm" disabled={busy} onClick={() => void addPhone()}>
                Set up
              </Button>
            }
          />
        </div>

        {ntfySetup && <NtfySetupPanel setup={ntfySetup.setup} onClose={() => setNtfySetup(null)} />}

        <button
          type="button"
          className="text-primary flex w-fit items-center gap-1 text-xs underline-offset-2 hover:underline"
          aria-expanded={showAdvanced}
          onClick={() => setShowAdvanced((v) => !v)}
        >
          <Webhook className="size-3.5" aria-hidden />
          {showAdvanced ? "Hide advanced" : "Advanced: Slack, Discord or custom webhook"}
        </button>

        {showAdvanced && (
          <div className="border-line flex flex-col gap-2 border-t pt-3">
            <select className={selectClass} aria-label="Channel type" value={hookType} onChange={(e) => setHookType(e.target.value as "Webhook" | "Ntfy")}>
              <option value="Webhook">Webhook (Slack, Discord, Mattermost, custom)</option>
              <option value="Ntfy">ntfy topic URL (my own server or topic)</option>
            </select>
            <Input aria-label="Label" placeholder="Label (optional)" maxLength={80} value={hookLabel} onChange={(e) => setHookLabel(e.target.value)} />
            <Input
              aria-label="Destination URL"
              type="url"
              autoComplete="off"
              placeholder="https://…"
              value={hookTarget}
              onChange={(e) => setHookTarget(e.target.value)}
            />
            <p className="text-muted-foreground text-[11px]">
              The URL is stored encrypted and never shown again. Webhook URLs act like a password, so treat them like one.
            </p>
            <div>
              <Button
                type="button"
                size="sm"
                disabled={busy || hookTarget.trim() === ""}
                onClick={async () => {
                  const res = await run(
                    () => api("POST", "/api/v1/alerts/channels", { type: hookType, label: hookLabel, target: hookTarget }),
                    "Could not add channel.",
                    "Channel added. Use “Send test” to confirm it works."
                  )
                  if (res) {
                    setHookLabel("")
                    setHookTarget("")
                  }
                }}
              >
                Add channel
              </Button>
            </div>
          </div>
        )}
      </section>

      {hasChannels && (
        <section aria-labelledby="channels-heading" className="border-line flex flex-col gap-3 rounded-md border p-4">
          <h2 id="channels-heading" className="text-sm font-semibold">Your channels</h2>
          <ul className="flex flex-col gap-2">
            {state.channels.map((c) => (
              <li key={c.id} className="border-line flex flex-col gap-1 rounded-md border p-3 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium">
                    {c.label}{" "}
                    <span className="text-muted-foreground font-normal">
                      · {c.type === "BrowserPush" ? "Browser" : c.type}
                      {c.targetHint ? ` · ${c.targetHint}` : ""}
                    </span>
                  </span>
                  <span className="flex gap-1.5">
                    <Button type="button" size="sm" disabled={busy} onClick={() => void testChannel(c)}>
                      Send test
                    </Button>
                    {c.type === "Ntfy" && (
                      <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void showNtfy(c.id)}>
                        Show setup
                      </Button>
                    )}
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() =>
                        void run(() => api("PUT", `/api/v1/alerts/channels/${c.id}`, { isEnabled: !c.isEnabled }), "Could not update channel.")
                      }
                    >
                      {c.isEnabled ? "Pause" : "Enable"}
                    </Button>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      aria-label={`Remove ${c.label}`}
                      onClick={() => void run(() => api("DELETE", `/api/v1/alerts/channels/${c.id}`), "Could not remove channel.")}
                    >
                      Remove
                    </Button>
                  </span>
                </div>
                <p className="text-muted-foreground">
                  {c.isEnabled ? "Active" : "Paused"}
                  {c.lastDeliveredAt && <> · last delivered <RelativeTime iso={c.lastDeliveredAt} /></>}
                </p>
                {c.lastError && <p className="text-severity-critical">{c.lastError}</p>}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}

function ChannelCard({
  icon,
  title,
  text,
  action,
  note,
}: {
  icon: React.ReactNode
  title: string
  text: string
  action: React.ReactNode
  note?: string
}) {
  return (
    <div className="border-line flex flex-col gap-2 rounded-md border p-3 text-xs">
      <div className="flex items-center gap-2 font-medium">
        {icon}
        {title}
      </div>
      <p className="text-muted-foreground flex-1">{text}</p>
      {note && <p className="text-muted-foreground text-[11px] italic">{note}</p>}
      {action && <div>{action}</div>}
    </div>
  )
}
