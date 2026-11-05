import { NextResponse, type NextRequest } from "next/server"
import { hasSessionCookie } from "@/lib/auth"

const PUBLIC_PATHS = new Set(["/login", "/register"])
// Reachable signed in or out: the link in a verification email can be opened from any session.
const ALWAYS_OPEN_PATHS = new Set(["/verify-email"])

export function proxy(request: NextRequest) {
  const signedIn = hasSessionCookie(request.cookies.getAll())
  const { pathname } = request.nextUrl
  if (ALWAYS_OPEN_PATHS.has(pathname)) {
    return NextResponse.next()
  }

  const isPublic = PUBLIC_PATHS.has(pathname)

  if (!signedIn && !isPublic) {
    const url = request.nextUrl.clone()
    url.pathname = "/login"
    if (pathname !== "/") {
      url.searchParams.set("next", pathname)
    }
    return NextResponse.redirect(url)
  }

  if (signedIn && isPublic) {
    return NextResponse.redirect(new URL("/", request.url))
  }

  return NextResponse.next()
}

export const config = {
  matcher: [
    "/((?!api|_next/static|_next/image|favicon.ico|sw.js|sitemap.xml|robots.txt).*)",
  ],
}
