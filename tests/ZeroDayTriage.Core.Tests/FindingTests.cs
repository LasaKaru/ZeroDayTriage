using FluentAssertions;
using ZeroDayTriage.Core.Model;
using Xunit;

namespace ZeroDayTriage.Core.Tests;

public sealed class FindingTests
{
    private static Finding Sample(string title = "Kerberoastable account: SVC_SQL") => new()
    {
        Title = title,
        Source = "sharphound",
        Domain = AssetDomain.ActiveDirectory,
        Principal = "EVILCORP\\SVC_SQL",
        Technique = "T1558.003",
    };

    [Fact]
    public void WithComputedId_is_deterministic_for_equivalent_findings()
    {
        var a = Sample().WithComputedId();
        var b = Sample().WithComputedId();

        a.Id.Should().Be(b.Id);
        a.Id.Should().HaveLength(16); // 8 bytes hex
    }

    [Fact]
    public void WithComputedId_differs_when_load_bearing_fields_change()
    {
        var baseline = Sample().WithComputedId();

        Sample("Kerberoastable account: SVC_WEB").WithComputedId().Id.Should().NotBe(baseline.Id);
        (Sample() with { Source = "netexec" }).WithComputedId().Id.Should().NotBe(baseline.Id);
        (Sample() with { Principal = "EVILCORP\\OTHER" }).WithComputedId().Id.Should().NotBe(baseline.Id);
    }

    [Theory]
    [InlineData("  Kerberoastable account: SVC_SQL  ")]
    [InlineData("kerberoastable account: svc_sql")]
    public void WithComputedId_ignores_case_and_surrounding_whitespace(string title)
    {
        var canonical = Sample().WithComputedId();
        var variant = Sample(title).WithComputedId();

        variant.Id.Should().Be(canonical.Id);
    }

    [Fact]
    public void HasTag_is_case_insensitive()
    {
        var finding = Sample() with { Tags = new[] { "Kerberoastable", "AD" } };

        finding.HasTag("kerberoastable").Should().BeTrue();
        finding.HasTag("KERBEROASTABLE").Should().BeTrue();
        finding.HasTag("dcsync").Should().BeFalse();
    }

    [Fact]
    public void Property_returns_value_or_null()
    {
        var finding = Sample() with
        {
            Properties = new Dictionary<string, string> { ["spn"] = "MSSQLSvc/db01" },
        };

        finding.Property("spn").Should().Be("MSSQLSvc/db01");
        finding.Property("missing").Should().BeNull();
    }

    [Fact]
    public void Defaults_are_safe_empty_collections()
    {
        var finding = Sample();

        finding.Tags.Should().BeEmpty();
        finding.Properties.Should().BeEmpty();
        finding.Severity.Should().Be(Severity.Info);
        finding.Confidence.Should().Be(Confidence.Suspected);
    }
}
