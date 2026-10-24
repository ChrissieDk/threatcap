using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Normalization;
using Threatwatch.Ingestion.Providers;

namespace Threatwatch.Tests;

public class CanonicalIdSelectorTests
{
    [Fact]
    public void PrefersCveOverGhsaAndSourceId()
    {
        var result = CanonicalIdSelector.Select("GHSA-abc-123", ["GHSA-abc-123", "CVE-2024-1234"]);
        Assert.Equal("CVE-2024-1234", result);
    }

    [Fact]
    public void PrefersGhsaOverSourceId()
    {
        var result = CanonicalIdSelector.Select("OSV-2024-1", ["GHSA-xxxx-yyyy"]);
        Assert.Equal("GHSA-xxxx-yyyy", result);
    }

    [Fact]
    public void FallsBackToOtherAliasThenRecordId()
    {
        Assert.Equal("PYSEC-1", CanonicalIdSelector.Select("OSV-2024-42", ["PYSEC-1"]));
        Assert.Equal("OSV-2024-42", CanonicalIdSelector.Select("OSV-2024-42", []));
    }

    [Fact]
    public void ClassifiesAliases()
    {
        Assert.Equal(AliasType.Cve, CanonicalIdSelector.Classify("CVE-2024-1"));
        Assert.Equal(AliasType.Ghsa, CanonicalIdSelector.Classify("GHSA-1"));
        Assert.Equal(AliasType.Other, CanonicalIdSelector.Classify("OSV-1"));
    }
}

public class PackageNameNormalizerTests
{
    [Theory]
    [InlineData("Lodash ", "lodash")]
    [InlineData("  React  ", "react")]
    [InlineData("NEXT", "next")]
    public void NormalizesToLowercaseTrimmed(string input, string expected)
    {
        Assert.Equal(expected, PackageNameNormalizer.Normalize(input));
    }

    [Fact]
    public void ThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => PackageNameNormalizer.Normalize(null!));
    }

    [Theory]
    [InlineData("npm", Ecosystem.Npm)]
    [InlineData("NuGet", Ecosystem.NuGet)]
    [InlineData("PyPI", Ecosystem.PyPI)]
    [InlineData("crates.io", Ecosystem.Cargo)]
    [InlineData("debian", Ecosystem.Linux)]
    [InlineData(null, Ecosystem.Other)]
    [InlineData("something-else", Ecosystem.Other)]
    public void MapsEcosystems(string? input, Ecosystem expected)
    {
        Assert.Equal(expected, PackageNameNormalizer.MapEcosystem(input));
    }
}

public class CvssParserTests
{
    [Theory]
    [InlineData(9.8, Severity.Critical)]
    [InlineData(9.0, Severity.Critical)]
    [InlineData(7.0, Severity.High)]
    [InlineData(4.0, Severity.Medium)]
    [InlineData(0.5, Severity.Low)]
    [InlineData(0.0, Severity.Unknown)]
    public void MapsBaseScoreToBand(double score, Severity expected)
    {
        Assert.Equal(expected, CvssParser.Band((decimal)score));
    }

    [Theory]
    [InlineData("9.8", 9.8)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 3.1)]
    [InlineData("7.5 CVSS:3.1/AV:N", 7.5)]
    public void ExtractsScoreFromFreeText(string input, double? expected)
    {
        var result = CvssParser.ExtractScore(input);
        Assert.Equal(expected.HasValue ? (decimal?)expected.Value : null, result);
    }
}

public class Rfc3339ParsingTests
{
    [Fact]
    public void ParsesUtcTimestamp()
    {
        var dto = OsvRecord.ParseRfc3339("2024-03-01T12:30:00Z");
        Assert.NotNull(dto);
        Assert.Equal(TimeSpan.Zero, dto!.Value.Offset);
        Assert.Equal(new DateTimeOffset(2024, 3, 1, 12, 30, 0, TimeSpan.Zero), dto.Value);
    }

    [Fact]
    public void ParsesOffsetTimestampPreservingOffset()
    {
        var dto = OsvRecord.ParseRfc3339("2024-03-01T14:30:00+02:00");
        Assert.NotNull(dto);
        Assert.Equal(new DateTimeOffset(2024, 3, 1, 14, 30, 0, TimeSpan.FromHours(2)), dto!.Value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-date")]
    public void ReturnsNullForInvalidInput(string? input)
    {
        Assert.Null(OsvRecord.ParseRfc3339(input));
    }
}
