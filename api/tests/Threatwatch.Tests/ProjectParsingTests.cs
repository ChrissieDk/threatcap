using Threatwatch.Core.Enums;
using Threatwatch.Core.Projects;

namespace Threatwatch.Tests;

public class VersionComparerTests
{
    [Theory]
    [InlineData(Ecosystem.Npm, "1.2.3", "1.2.4", -1)]
    [InlineData(Ecosystem.Npm, "1.10.0", "1.9.9", 1)]
    [InlineData(Ecosystem.Npm, "1.0.0-beta.2", "1.0.0", -1)]
    [InlineData(Ecosystem.Npm, "1.0.0-alpha.1", "1.0.0-alpha.beta", -1)]
    [InlineData(Ecosystem.Npm, "v2.0.0+build5", "2.0.0", 0)]
    [InlineData(Ecosystem.NuGet, "1.2.3.4", "1.2.3.5", -1)]
    [InlineData(Ecosystem.NuGet, "13.0.1", "13.0.3", -1)]
    [InlineData(Ecosystem.Go, "v1.2.3", "v1.2.3", 0)]
    [InlineData(Ecosystem.PyPI, "1.0", "1.0.0", 0)]
    [InlineData(Ecosystem.PyPI, "1.0rc1", "1.0", -1)]
    [InlineData(Ecosystem.PyPI, "1.0a1", "1.0b1", -1)]
    [InlineData(Ecosystem.PyPI, "1.0.post1", "1.0", 1)]
    [InlineData(Ecosystem.PyPI, "1.0.dev1", "1.0a1", -1)]
    [InlineData(Ecosystem.PyPI, "1!0.5", "2.0", 1)]
    [InlineData(Ecosystem.Maven, "5.3.30.RELEASE", "5.3.30", 0)]
    [InlineData(Ecosystem.Maven, "2.0-SNAPSHOT", "2.0", -1)]
    public void Orders_versions(Ecosystem eco, string a, string b, int expected) =>
        Assert.Equal(expected, Math.Sign(VersionComparer.Compare(eco, a, b)));

    [Theory]
    [InlineData("")]
    [InlineData("latest")]
    [InlineData("abc")]
    public void Rejects_unparseable(string raw) =>
        Assert.False(VersionComparer.TryParse(Ecosystem.Npm, raw, out _));
}

public class OsvRangeEvaluatorTests
{
    private const string Lodash = """[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]""";
    private const string Windowed = """[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.5.1"},{"introduced":"3.0.0"},{"last_affected":"3.1.0"}]}]""";

    [Theory]
    [InlineData("4.17.20", RangeVerdict.Affected, "4.17.21")]
    [InlineData("4.17.21", RangeVerdict.NotAffected, null)]
    [InlineData("5.0.0", RangeVerdict.NotAffected, null)]
    [InlineData("0.0.1", RangeVerdict.Affected, "4.17.21")]
    public void Introduced_zero_to_fixed(string version, RangeVerdict verdict, string? fix)
    {
        var r = OsvRangeEvaluator.Evaluate(Ecosystem.Npm, Lodash, version);
        Assert.Equal(verdict, r.Verdict);
        Assert.Equal(fix, r.FixedIn);
    }

    [Theory]
    [InlineData("1.9.0", RangeVerdict.NotAffected)]
    [InlineData("2.4.0", RangeVerdict.Affected)]
    [InlineData("2.5.1", RangeVerdict.NotAffected)]
    [InlineData("3.0.5", RangeVerdict.Affected)]
    [InlineData("3.1.0", RangeVerdict.Affected)]
    [InlineData("3.1.1", RangeVerdict.NotAffected)]
    public void Handles_multiple_windows_and_last_affected(string version, RangeVerdict verdict) =>
        Assert.Equal(verdict, OsvRangeEvaluator.Evaluate(Ecosystem.Npm, Windowed, version).Verdict);

    [Fact]
    public void Git_only_ranges_and_bad_versions_are_unknown()
    {
        Assert.Equal(RangeVerdict.Unknown, OsvRangeEvaluator.Evaluate(Ecosystem.Npm, """[{"type":"GIT","events":[{"introduced":"abc"}]}]""", "1.0.0").Verdict);
        Assert.Equal(RangeVerdict.Unknown, OsvRangeEvaluator.Evaluate(Ecosystem.Npm, Lodash, null).Verdict);
        Assert.Equal(RangeVerdict.Unknown, OsvRangeEvaluator.Evaluate(Ecosystem.Npm, "not json", "1.0.0").Verdict);
        Assert.Equal(RangeVerdict.Unknown, OsvRangeEvaluator.Evaluate(Ecosystem.Npm, "[]", "1.0.0").Verdict);
    }

    [Fact]
    public void Reads_ranges_as_stored_by_the_upserter()
    {
        // The upserter serializes OsvRange objects, which also emit computed Event/Value fields.
        var stored = """[{"type":"ECOSYSTEM","repo":null,"events":[{"introduced":"0","fixed":null,"last_affected":null,"limit":null,"Event":"introduced","Value":"0"},{"introduced":null,"fixed":"1.2.3","last_affected":null,"limit":null,"Event":"fixed","Value":"1.2.3"}]}]""";
        var r = OsvRangeEvaluator.Evaluate(Ecosystem.PyPI, stored, "1.2.2");
        Assert.Equal(RangeVerdict.Affected, r.Verdict);
        Assert.Equal("1.2.3", r.FixedIn);
    }
}

public class DependencyFileParserTests
{
    private static ParsedDependency One(ParseResult r, string name) => r.Dependencies.Single(d => d.Name == name);

    [Theory]
    [InlineData("4.17.21", "4.17.21", VersionKind.Exact)]
    [InlineData("^4.17.0", "4.17.0", VersionKind.Declared)]
    [InlineData("~1.2", "1.2", VersionKind.Declared)]
    [InlineData(">=2.0.0 <3.0.0", "2.0.0", VersionKind.Declared)]
    [InlineData("1.x", "1.0", VersionKind.Declared)]
    [InlineData("^1.0.0 || ^2.0.0", "1.0.0", VersionKind.Declared)]
    public void Resolves_npm_specs(string spec, string version, VersionKind kind) =>
        Assert.Equal((version, kind), DependencyFileParser.ResolveNpmSpec(spec));

    [Theory]
    [InlineData("*")]
    [InlineData("latest")]
    [InlineData("github:user/repo")]
    [InlineData("workspace:*")]
    [InlineData("<2.0.0")]
    [InlineData("file:../x")]
    public void Unresolvable_npm_specs_have_no_version(string spec) =>
        Assert.Null(DependencyFileParser.ResolveNpmSpec(spec).Version);

    [Fact]
    public void Parses_package_json()
    {
        var r = DependencyFileParser.Parse("package.json", """
            { "name": "x", "dependencies": { "lodash": "^4.17.0", "@scope/Pkg": "1.0.0" },
              "devDependencies": { "vitest": "^5.0.0" } }
            """);
        Assert.Equal(3, r.Dependencies.Count);
        Assert.True(One(r, "vitest").IsDev);
        Assert.Equal(VersionKind.Exact, One(r, "@scope/pkg").Kind);
        Assert.All(r.Dependencies, d => Assert.True(d.IsDirect));
    }

    [Fact]
    public void Parses_package_lock_v3_with_nested_modules()
    {
        var r = DependencyFileParser.Parse("package-lock.json", """
            { "lockfileVersion": 3, "packages": {
              "": { "name": "root" },
              "node_modules/lodash": { "version": "4.17.20" },
              "node_modules/a/node_modules/@s/b": { "version": "1.0.0", "dev": true },
              "node_modules/local": { "link": true, "resolved": "../local" } } }
            """);
        Assert.Equal(2, r.Dependencies.Count);
        Assert.Equal("4.17.20", One(r, "lodash").Version);
        Assert.True(One(r, "@s/b").IsDev);
    }

    [Fact]
    public void Parses_yarn_classic_and_berry()
    {
        var classic = DependencyFileParser.Parse("yarn.lock", "\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.24.0\"\n  resolved \"x\"\n\nlodash@^4.17.0:\n  version \"4.17.21\"\n");
        Assert.Equal(2, classic.Dependencies.Count);
        Assert.Equal("7.24.0", One(classic, "@babel/core").Version);

        var berry = DependencyFileParser.Parse("yarn.lock", "\"lodash@npm:^4.17.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n");
        Assert.Equal("4.17.21", One(berry, "lodash").Version);
        Assert.Single(berry.Dependencies);
    }

    [Fact]
    public void Parses_pnpm_lock_current_and_legacy()
    {
        var v9 = DependencyFileParser.Parse("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        version: 4.17.21\n\npackages:\n\n  '@babel/core@7.24.0':\n    resolution: {integrity: x}\n\n  lodash@4.17.21:\n    resolution: {integrity: y}\n\nsnapshots:\n  lodash@4.17.21: {}\n");
        Assert.Equal(2, v9.Dependencies.Count);
        Assert.Equal("7.24.0", One(v9, "@babel/core").Version);

        var v6 = DependencyFileParser.Parse("pnpm-lock.yaml", "packages:\n\n  /lodash@4.17.21:\n    dev: false\n  /@types/node@20.1.0(x):\n    dev: true\n");
        Assert.Equal(2, v6.Dependencies.Count);
        Assert.Equal("20.1.0", One(v6, "@types/node").Version);
    }

    [Fact]
    public void Parses_requirements_txt()
    {
        var r = DependencyFileParser.Parse("requirements.txt", """
            # comment
            -r other.txt
            Django==3.2.0
            Flask_Login >= 0.6 ; python_version > "3"
            requests[security]~=2.25.0  # inline
            numpy<2
            git+https://github.com/x/y.git
            """);
        Assert.Equal(["django", "flask-login", "numpy", "requests"], r.Dependencies.Select(d => d.Name).Order());
        Assert.Equal(VersionKind.Exact, One(r, "django").Kind);
        Assert.Equal("0.6", One(r, "flask-login").Version);
        Assert.Null(One(r, "numpy").Version);
    }

    [Fact]
    public void Parses_python_lockfiles()
    {
        var poetry = DependencyFileParser.Parse("poetry.lock", "[[package]]\nname = \"Django\"\nversion = \"3.2.0\"\ndescription = \"x\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.25.1\"\n\n[metadata]\nlock-version = \"2.0\"\n");
        Assert.Equal(["django", "requests"], poetry.Dependencies.Select(d => d.Name).Order());
        Assert.Equal("3.2.0", One(poetry, "django").Version);

        var uv = DependencyFileParser.Parse("uv.lock", "[[package]]\nname = \"myapp\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n[[package]]\nname = \"flask\"\nversion = \"2.0.1\"\nsource = { registry = \"https://pypi.org/simple\" }\n");
        Assert.Equal(["flask"], uv.Dependencies.Select(d => d.Name));

        var pipenv = DependencyFileParser.Parse("Pipfile.lock", """{ "default": { "Django": { "version": "==3.2.0" } }, "develop": { "pytest": { "version": "==7.0.0" } } }""");
        Assert.Equal("3.2.0", One(pipenv, "django").Version);
        Assert.True(One(pipenv, "pytest").IsDev);
    }

    [Fact]
    public void Parses_csproj_props_and_packages_config()
    {
        var csproj = DependencyFileParser.Parse("App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
              <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
              <PackageReference Include="Serilog"><Version>[3.0.0,4.0.0)</Version></PackageReference>
              <PackageReference Include="Analyzers" Version="1.0.0" PrivateAssets="all" />
              <PackageReference Include="Prop" Version="$(PropVersion)" />
            </ItemGroup></Project>
            """);
        Assert.Equal(4, csproj.Dependencies.Count);
        Assert.Equal("13.0.1", One(csproj, "newtonsoft.json").Version);
        Assert.Equal("3.0.0", One(csproj, "serilog").Version);
        Assert.True(One(csproj, "analyzers").IsDev);
        Assert.Null(One(csproj, "prop").Version);

        var props = DependencyFileParser.Parse("Directory.Packages.props", """<Project><ItemGroup><PackageVersion Include="Dapper" Version="2.1.0" /></ItemGroup></Project>""");
        Assert.Equal("2.1.0", One(props, "dapper").Version);

        var config = DependencyFileParser.Parse("packages.config", """<packages><package id="Foo" version="1.2.3" /></packages>""");
        Assert.Equal("1.2.3", One(config, "foo").Version);
    }

    [Fact]
    public void Rejects_xml_with_dtd()
    {
        var r = DependencyFileParser.Parse("App.csproj", """<!DOCTYPE x [<!ENTITY a "b">]><Project />""");
        Assert.Empty(r.Dependencies);
        Assert.NotEmpty(r.Warnings);
    }

    [Fact]
    public void Parses_go_mod()
    {
        var r = DependencyFileParser.Parse("go.mod", """
            module example.com/app
            go 1.22
            require github.com/gin-gonic/gin v1.9.0
            require (
                golang.org/x/net v0.17.0
                github.com/old/lib v2.0.0+incompatible // indirect
            )
            replace x => y v1.0.0
            """);
        Assert.Equal(3, r.Dependencies.Count);
        Assert.True(One(r, "github.com/gin-gonic/gin").IsDirect);
        Assert.False(One(r, "github.com/old/lib").IsDirect);
        Assert.Equal("v2.0.0", One(r, "github.com/old/lib").Version);
    }

    [Fact]
    public void Parses_cargo_files()
    {
        var lockfile = DependencyFileParser.Parse("Cargo.lock", "[[package]]\nname = \"me\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n");
        Assert.Equal(["serde"], lockfile.Dependencies.Select(d => d.Name));

        var toml = DependencyFileParser.Parse("Cargo.toml", "[package]\nname=\"me\"\n\n[dependencies]\nserde = \"1.0\"\ntokio = { version = \"1.20\", features = [\"full\"] }\nlocal = { path = \"../x\" }\n\n[dev-dependencies.mockall]\nversion = \"0.11\"\n");
        Assert.Equal(3, toml.Dependencies.Count);
        Assert.True(One(toml, "mockall").IsDev);
    }

    [Fact]
    public void Parses_pom_with_properties_and_management()
    {
        var r = DependencyFileParser.Parse("pom.xml", """
            <project xmlns="http://maven.apache.org/POM/4.0.0"><properties><spring.version>5.3.30</spring.version></properties>
            <dependencyManagement><dependencies><dependency><groupId>org.x</groupId><artifactId>managed</artifactId><version>2.0.0</version></dependency></dependencies></dependencyManagement>
            <dependencies>
              <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>${spring.version}</version></dependency>
              <dependency><groupId>org.x</groupId><artifactId>managed</artifactId></dependency>
              <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency>
            </dependencies>
            <build><plugins><plugin><dependencies><dependency><groupId>p</groupId><artifactId>plug</artifactId><version>1</version></dependency></dependencies></plugin></plugins></build></project>
            """);
        Assert.Equal(3, r.Dependencies.Count);
        Assert.Equal("5.3.30", One(r, "org.springframework:spring-core").Version);
        Assert.Equal("2.0.0", One(r, "org.x:managed").Version);
        Assert.True(One(r, "junit:junit").IsDev);
    }

    [Fact]
    public void Parses_cyclonedx_and_spdx()
    {
        var cdx = DependencyFileParser.Parse("bom.json", """
            { "bomFormat": "CycloneDX", "components": [
              { "purl": "pkg:npm/%40babel/core@7.24.0", "components": [ { "purl": "pkg:pypi/Django@3.2.0" } ] },
              { "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar" },
              { "purl": "pkg:golang/golang.org/x/net@v0.17.0" },
              { "purl": "pkg:deb/debian/openssl@1.1" } ] }
            """);
        Assert.Equal(4, cdx.Dependencies.Count);
        Assert.Equal("org.apache.logging.log4j:log4j-core", One(cdx, "org.apache.logging.log4j:log4j-core").Name);
        Assert.Equal("@babel/core", One(cdx, "@babel/core").Name);

        var spdx = DependencyFileParser.Parse("sbom.json", """
            { "spdxVersion": "SPDX-2.3", "packages": [ { "externalRefs": [ { "referenceType": "purl", "referenceLocator": "pkg:nuget/Newtonsoft.Json@13.0.1" } ] } ] }
            """);
        Assert.Equal("13.0.1", One(spdx, "newtonsoft.json").Version);
    }

    [Fact]
    public void Bad_input_yields_warnings_not_exceptions()
    {
        Assert.NotEmpty(DependencyFileParser.Parse("package.json", "{ not json").Warnings);
        Assert.NotEmpty(DependencyFileParser.Parse("notes.txt", "hello").Warnings);
        Assert.NotEmpty(DependencyFileParser.Parse("x.json", """{"foo":1}""").Warnings);
    }

    [Fact]
    public void Merge_prefers_exact_versions_and_marks_direct()
    {
        var manifest = DependencyFileParser.Parse("package.json", """{ "dependencies": { "lodash": "^4.17.0", "left": "^1.0.0" } }""").Dependencies;
        var lockfile = DependencyFileParser.Parse("package-lock.json", """
            { "packages": { "node_modules/lodash": { "version": "4.17.20" }, "node_modules/transitive": { "version": "2.0.0" } } }
            """).Dependencies;

        var merged = DependencyMerger.Merge(manifest.Concat(lockfile));
        var lodash = merged.Single(d => d.Name == "lodash");
        Assert.Equal(("4.17.20", VersionKind.Exact, true), (lodash.Version, lodash.Kind, lodash.IsDirect));
        Assert.False(merged.Single(d => d.Name == "transitive").IsDirect);
        Assert.Equal(VersionKind.Declared, merged.Single(d => d.Name == "left").Kind);
        Assert.Equal(3, merged.Count);
    }
}
