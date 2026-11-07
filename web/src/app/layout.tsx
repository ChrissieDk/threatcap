import type { Metadata } from "next"
import { Suspense } from "react"
import { Atkinson_Hyperlegible_Mono, Host_Grotesk, Inter } from "next/font/google"
import "./globals.css"
import { ShellGate } from "@/components/layout/shell-gate"
import { TooltipProvider } from "@/components/ui/tooltip"

const inter = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-inter",
})

const hostGrotesk = Host_Grotesk({
  subsets: ["latin"],
  weight: ["400", "500"],
  display: "swap",
  variable: "--font-host-grotesk",
  preload: false,
})

const atkinsonMono = Atkinson_Hyperlegible_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  display: "swap",
  variable: "--font-atkinson-mono",
  preload: false,
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
    <html lang="en" className={`${inter.variable} ${hostGrotesk.variable} ${atkinsonMono.variable}`}>
      <body className="font-sans antialiased">
        <TooltipProvider>
          <Suspense fallback={children}>
            <ShellGate>{children}</ShellGate>
          </Suspense>
        </TooltipProvider>
      </body>
    </html>
  )
}
