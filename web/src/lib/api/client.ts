import { cookies, headers as requestHeaders } from "next/headers"

const API_BASE: string = process.env.API_URL ?? "http://localhost:5080"

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
  }
}

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`
}

export async function apiGet<T>(path: string): Promise<T> {
  let res: Response
  try {
    const apiKey = process.env.API_KEY
    if (!apiKey) {
      throw new ApiError(0, "API_KEY is not configured")
    }
    const headers: Record<string, string> = { Authorization: `Bearer ${apiKey}` }
    // Pass the visitor's address on (Caddy sets it) so the API rate-limits each client separately,
    // rather than counting every server-rendered page against this server's own address.
    const forwarded = (await requestHeaders()).get("x-forwarded-for")
    if (forwarded) headers["X-Forwarded-For"] = forwarded
    const session = (await cookies())
      .getAll()
      .map((cookie) => `${cookie.name}=${cookie.value}`)
      .join("; ")
    if (session) {
      headers.Cookie = session
    }
    res = await fetch(apiUrl(path), {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(20_000),
    })
  } catch (err) {
    if (err instanceof ApiError) throw err
    throw new ApiError(0, err instanceof Error ? err.message : "Failed to reach the API")
  }
  if (!res.ok) {
    throw new ApiError(res.status, `API request failed with ${res.status}`)
  }
  return (await res.json()) as T
}
