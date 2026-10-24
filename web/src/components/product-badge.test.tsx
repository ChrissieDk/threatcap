import { describe, expect, it } from "vitest"
import { render, screen } from "@testing-library/react"
import { ProductBadge } from "@/components/product-badge"

describe("ProductBadge", () => {
  it("renders vendor tag and product name", () => {
    render(
      <ProductBadge
        primaryVendor="PyPI"
        primaryProduct="Django"
        productType="Library"
      />
    )
    expect(screen.getByText("[PyPI]")).toBeInTheDocument()
    expect(screen.getByText("Django")).toBeInTheDocument()
  })

  it("renders just the product when the vendor is missing", () => {
    render(
      <ProductBadge
        primaryVendor={null}
        primaryProduct="Windows"
        productType="Os"
      />
    )
    expect(screen.getByText("Windows")).toBeInTheDocument()
  })

  it("renders a fallback when neither vendor nor product is present", () => {
    render(
      <ProductBadge primaryVendor={null} primaryProduct={null} productType={null} />
    )
    expect(screen.getByText("—")).toBeInTheDocument()
  })

  it("handles unknown product type gracefully", () => {
    render(
      <ProductBadge
        primaryVendor="Acme"
        primaryProduct="Widget"
        productType={null}
      />
    )
    expect(screen.getByText("[Acme]")).toBeInTheDocument()
    expect(screen.getByText("Widget")).toBeInTheDocument()
  })
})
