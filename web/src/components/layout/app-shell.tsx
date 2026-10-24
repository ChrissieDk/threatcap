"use client"

import { Suspense, useEffect, useState } from "react"
import { usePathname, useRouter } from "next/navigation"
import { Menu } from "lucide-react"
import { Brand, SidebarNav } from "@/components/layout/sidebar"
import { GlobalSearch } from "@/components/layout/global-search"
import { NotificationBell } from "@/components/layout/notification-bell"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet"
import { endSession } from "@/lib/auth"

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  if (pathname === "/login" || pathname === "/register") {
    return <>{children}</>
  }

  return (
    <div className="flex min-h-screen">
      <Suspense fallback={null}>
        <Sidebar />
      </Suspense>

      <div className="flex min-w-0 flex-1 flex-col lg:pl-56">
        <header className="border-line bg-background/80 sticky top-0 z-20 flex h-12 items-center gap-3 border-b px-4 backdrop-blur">
          <Suspense fallback={null}>
            <MobileNav />
          </Suspense>
          <div className="ml-auto flex w-full max-w-md items-center gap-2">
            <div className="min-w-0 flex-1">
              <GlobalSearch />
            </div>
            <NotificationBell />
            <AccountMenu />
          </div>
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 sm:px-6">
          {children}
        </main>
      </div>
    </div>
  )
}

function Sidebar() {
  const pathname = usePathname()
  return (
    <aside className="bg-surface border-line fixed inset-y-0 left-0 z-30 hidden w-56 flex-col border-r lg:flex">
      <Brand />
      <SidebarNav pathname={pathname} />
    </aside>
  )
}

function MobileNav() {
  const pathname = usePathname()
  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="lg:hidden"
          aria-label="Open navigation menu"
        >
          <Menu className="size-4" aria-hidden />
        </Button>
      </SheetTrigger>
      <SheetContent aria-describedby={undefined}>
        <SheetTitle className="sr-only">Navigation</SheetTitle>
        <Brand />
        <SidebarNav pathname={pathname} />
      </SheetContent>
    </Sheet>
  )
}

function AccountMenu() {
  const router = useRouter()
  const [email, setEmail] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    let cancelled = false
    fetch("/api/v1/auth/me")
      .then(async (res) => {
        if (res.status === 401) {
          await endSession()
          router.push("/login")
          router.refresh()
          return
        }
        if (!res.ok) return
        const body = (await res.json()) as { email?: string }
        if (!cancelled) setEmail(body.email ?? null)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [router])

  async function signOut() {
    setPending(true)
    await endSession()
    router.push("/login")
    router.refresh()
  }

  return (
    <div className="flex items-center gap-2">
      {email && (
        <span className="text-muted-foreground hidden max-w-40 truncate text-xs sm:inline">
          {email}
        </span>
      )}
      <Button variant="ghost" size="sm" onClick={signOut} disabled={pending}>
        Sign out
      </Button>
    </div>
  )
}
