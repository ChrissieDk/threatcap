import { describe, expect, it } from "vitest"
import { render, screen } from "@testing-library/react"
import { SeverityBadge } from "@/components/severity-badge"

describe("SeverityBadge", () => {
  it("renders the severity label", () => {
    render(<SeverityBadge severity="Critical" />)
    expect(screen.getByText("Critical")).toBeInTheDocument()
  })

  it("renders a colored indicator dot", () => {
    const { container } = render(<SeverityBadge severity="High" />)
    expect(container.querySelector("span[aria-hidden]")).not.toBeNull()
  })
})
