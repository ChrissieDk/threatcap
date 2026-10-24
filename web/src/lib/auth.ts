export const SESSION_COOKIE = "threatwatch.session"
export const REQUEST_HEADER = "X-Threatwatch-Request"

export function hasSessionCookie(cookies: { name: string }[]): boolean {
  return cookies.some(
    (cookie) => cookie.name === SESSION_COOKIE || cookie.name.startsWith(`${SESSION_COOKIE}C`)
  )
}

export function safeNextPath(value: string | null): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) {
    return "/"
  }
  return value
}

export async function endSession(): Promise<void> {
  await fetch("/api/v1/auth/logout", {
    method: "POST",
    headers: { [REQUEST_HEADER]: "1" },
  }).catch(() => {})
}
