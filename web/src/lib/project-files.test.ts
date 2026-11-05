import { describe, expect, it } from "vitest"
import { detectFileName } from "@/lib/project-files"

describe("detectFileName", () => {
  it("recognizes common dependency files", () => {
    expect(detectFileName('{ "name": "x", "dependencies": { "a": "1.0.0" } }')).toBe("package.json")
    expect(detectFileName('{ "lockfileVersion": 3, "packages": {} }')).toBe("package-lock.json")
    expect(detectFileName('{ "bomFormat": "CycloneDX", "components": [] }')).toBe("bom.json")
    expect(detectFileName('<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="A" Version="1" /></ItemGroup></Project>')).toBe("pasted.csproj")
    expect(detectFileName("<project><modelVersion>4.0.0</modelVersion><dependencies/></project>")).toBe("pom.xml")
    expect(detectFileName("module example.com/app\n\ngo 1.22\n\nrequire github.com/x/y v1.0.0")).toBe("go.mod")
    expect(detectFileName("[package]\nname = \"a\"\n\n[dependencies]\nserde = \"1\"")).toBe("Cargo.toml")
    expect(detectFileName("[[package]]\nname = \"a\"")).toBe("Cargo.lock")
    expect(detectFileName("lockfileVersion: '9.0'\n\npackages:\n")).toBe("pnpm-lock.yaml")
    expect(detectFileName("django==3.2.0\nflask>=2.0")).toBe("requirements.txt")
  })
})
