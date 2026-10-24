import { ComingSoon } from "@/components/empty-state"

export const metadata = { title: "Incidents" }

export default function IncidentsPage() {
  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-base font-semibold">Incidents</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          Active security incidents affecting your followed technologies.
        </p>
      </div>
      <ComingSoon feature="Incidents" />
    </div>
  )
}
