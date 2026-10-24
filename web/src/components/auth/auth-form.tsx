"use client"

import { useState } from "react"
import Link from "next/link"
import { useRouter, useSearchParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { REQUEST_HEADER, safeNextPath } from "@/lib/auth"

type Mode = "login" | "register"

export function AuthForm({ mode }: { mode: Mode }) {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [confirm, setConfirm] = useState("")
  const [displayName, setDisplayName] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const isRegister = mode === "register"

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)

    if (isRegister && password !== confirm) {
      setError("Passwords do not match.")
      return
    }

    setPending(true)
    try {
      const res = await fetch(isRegister ? "/api/v1/auth/register" : "/api/v1/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [REQUEST_HEADER]: "1",
        },
        body: JSON.stringify({
          email,
          password,
          displayName: isRegister ? displayName : undefined,
        }),
      })

      if (!res.ok) {
        setError(await readError(res))
        return
      }

      router.push(safeNextPath(searchParams.get("next")))
      router.refresh()
    } catch {
      setError("Could not reach the server. Try again.")
    } finally {
      setPending(false)
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <form
        onSubmit={onSubmit}
        className="border-line bg-surface w-full max-w-sm rounded-md border p-6"
      >
        <h1 className="text-base font-semibold">{isRegister ? "Create account" : "Sign in"}</h1>
        <p className="text-muted-foreground mt-1 text-xs">
          {isRegister
            ? "Use a valid email. No verification message is sent."
            : "Sign in with your email and password."}
        </p>

        <div className="mt-5 flex flex-col gap-3">
          {isRegister && (
            <label className="flex flex-col gap-1 text-xs">
              Display name
              <Input
                value={displayName}
                onChange={(event) => setDisplayName(event.target.value)}
                autoComplete="nickname"
                maxLength={80}
                className="h-9 text-sm"
              />
            </label>
          )}
          <label className="flex flex-col gap-1 text-xs">
            Email
            <Input
              type="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="email"
              spellCheck={false}
              className="h-9 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Password
            <Input
              type="password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete={isRegister ? "new-password" : "current-password"}
              minLength={isRegister ? 12 : undefined}
              maxLength={128}
              aria-describedby={isRegister ? "password-rules" : undefined}
              className="h-9 text-sm"
            />
          </label>
          {isRegister && (
            <>
              <label className="flex flex-col gap-1 text-xs">
                Confirm password
                <Input
                  type="password"
                  required
                  value={confirm}
                  onChange={(event) => setConfirm(event.target.value)}
                  autoComplete="new-password"
                  minLength={12}
                  maxLength={128}
                  className="h-9 text-sm"
                />
              </label>
              <p id="password-rules" className="text-muted-foreground text-xs">
                At least 12 characters, with uppercase, lowercase, a number, and a symbol.
              </p>
            </>
          )}
        </div>

        {error && (
          <p role="alert" className="text-severity-critical mt-3 text-xs">
            {error}
          </p>
        )}

        <Button type="submit" className="mt-5 h-9 w-full text-sm" disabled={pending}>
          {pending ? "Please wait…" : isRegister ? "Create account" : "Sign in"}
        </Button>

        <p className="text-muted-foreground mt-4 text-xs">
          {isRegister ? (
            <>
              Already have an account?{" "}
              <Link href="/login" className="text-primary hover:underline">
                Sign in
              </Link>
            </>
          ) : (
            <>
              Need an account?{" "}
              <Link href="/register" className="text-primary hover:underline">
                Create one
              </Link>
            </>
          )}
        </p>
      </form>
    </main>
  )
}

async function readError(res: Response): Promise<string> {
  if (res.status === 429) {
    return "Too many attempts. Wait a minute and try again."
  }
  try {
    const body = (await res.json()) as { error?: { message?: string } }
    if (body.error?.message) return body.error.message
  } catch {
    // The response was not JSON.
  }
  return "Something went wrong. Try again."
}
