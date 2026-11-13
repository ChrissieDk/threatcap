import { apiUrl } from "@/lib/api/client"

export type PublicStats = {
  vulnerabilitiesPickedUp: number
  since: string | null
}

/**
 * Landing-page counter. Signed-out visitors have no session, so this sends only the API key,
 * and any failure just hides the counter rather than breaking the page.
 */
export async function getPublicStats(): Promise<PublicStats | null> {
  const apiKey = process.env.API_KEY
  if (!apiKey) return null
  try {
    const res = await fetch(apiUrl("/api/v1/stats/public"), {
      headers: { Authorization: `Bearer ${apiKey}` },
      next: { revalidate: 300 },
      signal: AbortSignal.timeout(5_000),
    })
    return res.ok ? ((await res.json()) as PublicStats) : null
  } catch {
    return null
  }
}
