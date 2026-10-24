import { connection } from "next/server"
import type { NextRequest } from "next/server"

const API_URL = process.env.API_URL ?? "http://localhost:5080"

async function proxyRequest(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  await connection()

  if (request.method !== "GET" && request.method !== "POST" && request.method !== "DELETE") {
    return Response.json(
      { error: { code: "validation_error", message: "Method not allowed." } },
      { status: 405 }
    )
  }

  const apiKey = process.env.API_KEY
  if (!apiKey) {
    return Response.json(
      { error: { code: "unauthorized", message: "API_KEY is not configured." } },
      { status: 500 }
    )
  }

  const { path } = await context.params
  if (path.some((segment) => segment === "" || segment === "." || segment === "..")) {
    return Response.json(
      { error: { code: "validation_error", message: "Invalid path." } },
      { status: 400 }
    )
  }

  const target = new URL(
    `/api/v1/${path.map(encodeURIComponent).join("/")}${request.nextUrl.search}`,
    API_URL
  )
  const headers = new Headers()
  headers.set("Accept", "application/json")
  headers.set("Authorization", `Bearer ${apiKey}`)

  const contentType = request.headers.get("content-type")
  if (contentType) headers.set("Content-Type", contentType)

  const cookie = request.headers.get("cookie")
  if (cookie) headers.set("Cookie", cookie)

  const browserRequest = request.headers.get("x-threatwatch-request")
  if (browserRequest) headers.set("X-Threatwatch-Request", browserRequest)

  const forwarded = request.headers.get("x-forwarded-for")
  if (forwarded) headers.set("X-Forwarded-For", forwarded)

  const upstream = await fetch(target, {
    method: request.method,
    headers,
    body: request.method === "GET" ? undefined : await request.arrayBuffer(),
    cache: "no-store",
    signal: AbortSignal.timeout(20_000),
  })

  const responseHeaders = new Headers()
  const responseType = upstream.headers.get("content-type")
  if (responseType) responseHeaders.set("content-type", responseType)
  for (const setCookie of upstream.headers.getSetCookie()) {
    responseHeaders.append("set-cookie", setCookie)
  }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  })
}

export const GET = proxyRequest
export const POST = proxyRequest
export const DELETE = proxyRequest
