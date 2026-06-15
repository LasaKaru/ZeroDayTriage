using FluentAssertions;
using ZeroDayTriage.Core.Model;
using Xunit;

namespace ZeroDayTriage.Core.Tests;

public sealed class FindingCorpusTests
{
    private static Finding Make(string title, string? principal = null, AssetDomain domain = AssetDomain.ActiveDirectory, params string[] tags) => new Finding
    {
        Title = title,
        Source = "test",
        Domain = domain,
        Principal = principal,
        Tags = tags,
    }.WithComputedId();

    [Theory]
    [InlineData("EVILCORP\\svc_sql", "svc_sql")]
    [InlineData("svc_sql@evilcorp.local", "svc_sql")]
    [InlineData("  SVC_SQL  ", "svc_sql")]
    [InlineData("evilcorp.local\\Administrator", "administrator")]
    public void Normalize_collapses_principal_forms(string input, string expected)
    {
        FindingCorpus.Normalize(input).Should().Be(expected);
    }

    [Fact]
    public void ForPrincipal_matches_across_naming_conventions()
    {
        var corpus = new FindingCorpus(new[]
        {
            Make("roastable", "EVILCORP\\SVC_SQL", AssetDomain.ActiveDirectory, "kerberoastable"),
            Make("acl", "svc_sql@evilcorp.local", AssetDomain.ActiveDirectory, "genericwrite"),
        });

        var hits = corpus.ForPrincipal("svc_sql").ToList();

        hits.Should().HaveCount(2);
        hits.Select(f => f.Title).Should().Contain(new[] { "roastable", "acl" });
    }

    [Fact]
    public void WithTag_is_case_insensitive_and_indexed()
    {
        var corpus = new FindingCorpus(new[]
        {
            Make("a", tags: "Kerberoastable"),
            Make("b", tags: "kerberoastable"),
            Make("c", tags: "dcsync"),
        });

        corpus.WithTag("KERBEROASTABLE").Should().HaveCount(2);
        corpus.HasTag("dcsync").Should().BeTrue();
        corpus.HasTag("nonexistent").Should().BeFalse();
    }

    [Fact]
    public void InDomain_partitions_by_battleground()
    {
        var corpus = new FindingCorpus(new[]
        {
            Make("ad", domain: AssetDomain.ActiveDirectory),
            Make("chain", domain: AssetDomain.SmartContract),
            Make("k8s", domain: AssetDomain.Kubernetes),
        });

        corpus.InDomain(AssetDomain.SmartContract).Should().ContainSingle(f => f.Title == "chain");
        corpus.InDomain(AssetDomain.Cloud).Should().BeEmpty();
    }

    [Fact]
    public void ById_returns_finding_or_null()
    {
        var finding = Make("a", tags: "x");
        var corpus = new FindingCorpus(new[] { finding });

        corpus.ById(finding.Id).Should().NotBeNull();
        corpus.ById("deadbeef").Should().BeNull();
    }

    [Fact]
    public void ForPrincipal_with_blank_returns_empty()
    {
        var corpus = new FindingCorpus(new[] { Make("a", "svc") });

        corpus.ForPrincipal("   ").Should().BeEmpty();
    }

    [Fact]
    public void Constructor_rejects_null()
    {
        var act = () => new FindingCorpus(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}
