"use client"

import { QRCodeSVG } from "qrcode.react"
import { Button } from "@/components/ui/button"
import type { NtfySetup } from "@/lib/api/types"

/** Instructions for subscribing a phone to a server-generated ntfy topic. */
export function NtfySetupPanel({ setup, onClose }: { setup: NtfySetup; onClose: () => void }) {
  const host = setup.server.replace(/^https?:\/\//, "")
  return (
    <div className="border-line bg-background flex flex-col gap-3 rounded-md border p-3 text-xs sm:flex-row">
      <div className="bg-white p-2 self-start rounded-md">
        <QRCodeSVG value={setup.topicUrl} size={120} title="Scan to open your alert topic" />
      </div>
      <div className="flex min-w-0 flex-1 flex-col gap-2">
        <p className="font-medium">Subscribe on your phone</p>
        <ol className="text-muted-foreground list-decimal pl-4">
          <li>Install the free ntfy app (iOS or Android).</li>
          <li>Scan the QR code, or tap <em>+</em> in the app and enter the topic below.</li>
          <li>Press “Send test” on the channel to check it works.</li>
        </ol>
        <p className="break-all">
          Topic: <code className="bg-surface rounded px-1">{setup.topic}</code>
          <br />
          Server: <code className="bg-surface rounded px-1">{host}</code>
        </p>
        <p className="text-muted-foreground">
          Anyone who knows this topic can read your alerts, so don’t share it.
        </p>
        <div className="flex gap-2">
          <Button asChild size="sm" variant="outline">
            <a href={`ntfy://${host}/${setup.topic}`}>Open in ntfy app</a>
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={onClose}>
            Done
          </Button>
        </div>
      </div>
    </div>
  )
}
