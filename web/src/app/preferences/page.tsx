import { ComingSoon } from "@/components/empty-state"

export const metadata = { title: "Preferences" }

export default function PreferencesPage() {
  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-base font-semibold">Preferences</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          Notification and display settings for your account.
        </p>
      </div>
      <ComingSoon feature="Preferences" />
    </div>
  )
}
