import type { ComponentType } from "react"
import Link from "next/link"
import {
  Activity,
  Boxes,
  LayoutDashboard,
  MessagesSquare,
  Radar,
  Rss,
  Settings,
  ShieldAlert,
} from "lucide-react"
import { cn } from "@/lib/utils"

export type NavItem = {
  href: string
  label: string
  icon: ComponentType<{ className?: string }>
}

export const NAV_SECTIONS: Array<{ label: string; items: NavItem[] }> = [
  {
    label: "Intelligence",
    items: [
      { href: "/", label: "Overview", icon: LayoutDashboard },
      { href: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
      { href: "/incidents", label: "Incidents", icon: Activity },
      { href: "/discussions", label: "Discussions", icon: MessagesSquare },
    ],
  },
  {
    label: "Personal",
    items: [
      { href: "/following", label: "Following", icon: Rss },
      { href: "/technologies", label: "Technologies", icon: Boxes },
      { href: "/preferences", label: "Preferences", icon: Settings },
    ],
  },
]

export function Brand() {
  return (
    <Link
      href="/"
      className="flex items-center gap-2 px-4 py-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-md"
      aria-label="Threatwatch home"
    >
      <Radar className="text-primary size-4" aria-hidden />
      <span className="text-sm font-semibold tracking-tight">Threatwatch</span>
    </Link>
  )
}

export function SidebarNav({ pathname }: { pathname: string }) {
  return (
    <nav aria-label="Primary" className="flex-1 overflow-y-auto px-2 pb-4">
      {NAV_SECTIONS.map((section) => (
        <div key={section.label} className="mt-4 first:mt-1">
          <p className="text-muted-foreground px-2 pb-1.5 text-[10px] font-medium tracking-[0.12em] uppercase">
            {section.label}
          </p>
          <ul className="flex flex-col gap-0.5">
            {section.items.map((item) => {
              const active =
                item.href === "/"
                  ? pathname === "/"
                  : pathname.startsWith(item.href)
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "flex items-center gap-2.5 rounded-md px-2 py-1.5 text-[13px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50",
                      active
                        ? "bg-surface-2 text-foreground"
                        : "text-muted-foreground hover:bg-surface-2/60 hover:text-foreground"
                    )}
                  >
                    <item.icon className="size-3.5 shrink-0" aria-hidden />
                    {item.label}
                  </Link>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </nav>
  )
}
