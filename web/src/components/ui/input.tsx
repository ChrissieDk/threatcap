import * as React from "react"

import { cn } from "@/lib/utils"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "file:text-foreground placeholder:text-muted-foreground selection:bg-primary/30 border-line-strong flex h-8 w-full min-w-0 rounded-md border bg-surface px-2.5 py-1 text-xs transition-[color,box-shadow] outline-none disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50",
        "focus-visible:border-primary focus-visible:ring-primary/30 focus-visible:ring-[3px]",
        className
      )}
      {...props}
    />
  )
}

export { Input }
