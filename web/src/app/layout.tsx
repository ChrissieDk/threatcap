import type { Metadata } from "next"
import { Suspense } from "react"
import { Inter } from "next/font/google"
import "./globals.css"
import { AppShell } from "@/components/layout/app-shell"
import { TooltipProvider } from "@/components/ui/tooltip"

const inter = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-inter",
})

export const metadata: Metadata = {
  title: {
    default: "Threatwatch",
    template: "%s · Threatwatch",
  },
  description: "Developer security intelligence dashboard",
}

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={inter.variable}>
      <body className="font-sans antialiased">
        <TooltipProvider>
          <Suspense fallback={children}>
            <AppShell>{children}</AppShell>
          </Suspense>
        </TooltipProvider>
      </body>
    </html>
  )
}
