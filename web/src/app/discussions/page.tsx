import { ComingSoon } from "@/components/empty-state"

export const metadata = { title: "Discussions" }

export default function DiscussionsPage() {
  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-base font-semibold">Discussions</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          Active security discussions affecting your followed technologies.
        </p>
      </div>
      <ComingSoon feature="Discussions" />
    </div>
  )
}
