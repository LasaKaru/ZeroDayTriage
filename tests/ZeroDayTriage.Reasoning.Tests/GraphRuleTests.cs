using FluentAssertions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning.Rules;
using Xunit;
using static ZeroDayTriage.Reasoning.Tests.Builders;

namespace ZeroDayTriage.Reasoning.Tests;

public sealed class ShortestPathToDomainAdminRuleTests
{
    private readonly ShortestPathToDomainAdminRule _sut = new();

    private static Finding Edge(string type, string from, string to) =>
        Finding($"{type}", from, properties: new Dictionary<string, string> { ["target"] = to }, tags: new[] { type });

    private static Finding Cred(string principal) =>
        Finding($"creds {principal}", principal, tags: new[] { "valid-credential" });

    [Fact]
    public void Resolves_a_full_path_from_foothold_to_domain_admins()
    {
        var corpus = Corpus(
            Cred("jdoe"),
            Edge("adminto", "jdoe", "ws01"),
            Edge("hassession", "ws01", "svc_adm"),
            Edge("memberof", "svc_adm", "domain admins"));

        var path = _sut.Evaluate(corpus).Single();

        path.Impact.Should().Be(Severity.Critical);
        path.Confidence.Should().Be(Confidence.Confirmed); // seed has valid creds
        path.Hops.Should().Be(3);
        path.Steps.Select(s => s.Technique).Should().Contain("T1003.001"); // session dump
        path.Rationale.Should().Contain("domain admins");
    }

    [Fact]
    public void Treats_a_dcsync_capable_principal_as_a_goal()
    {
        var corpus = Corpus(
            Cred("jdoe"),
            Edge("genericall", "jdoe", "svc_repl"),
            Finding("dcsync", "svc_repl", technique: "T1003.006", severity: Severity.Critical, tags: "dcsync"));

        var path = _sut.Evaluate(corpus).Single();

        path.Steps.Should().ContainSingle();
        path.Name.Should().Contain("svc_repl");
    }

    [Fact]
    public void Emits_nothing_without_an_owned_seed()
    {
        var corpus = Corpus(
            Edge("adminto", "jdoe", "ws01"),
            Edge("memberof", "jdoe", "domain admins"));

        _sut.Evaluate(corpus).Should().BeEmpty();
    }

    [Fact]
    public void Emits_nothing_when_no_path_reaches_a_goal()
    {
        var corpus = Corpus(Cred("jdoe"), Edge("canrdp", "jdoe", "ws01"));

        _sut.Evaluate(corpus).Should().BeEmpty();
    }
}

public sealed class LateralMovementRuleTests
{
    private readonly LateralMovementRule _sut = new();

    private static Finding Edge(string type, string from, string to) =>
        Finding($"{type}", from, properties: new Dictionary<string, string> { ["target"] = to }, tags: new[] { type });

    [Fact]
    public void Builds_a_hop_when_we_own_a_principal_with_an_exec_edge()
    {
        var corpus = Corpus(
            Finding("creds", "EVILCORP\\jdoe", tags: new[] { "valid-credential" }),
            Edge("adminto", "EVILCORP\\jdoe", "WS01"));

        var path = _sut.Evaluate(corpus).Single();

        path.Name.Should().Contain("WS01");
        path.Steps.Single().Technique.Should().Be("T1021.002");
    }

    [Fact]
    public void Does_not_move_using_principals_we_do_not_own()
    {
        var corpus = Corpus(Edge("adminto", "helpdesk", "WS01"));

        _sut.Evaluate(corpus).Should().BeEmpty();
    }

    [Fact]
    public void Covers_psremote_rdp_and_dcom_edges()
    {
        var corpus = Corpus(
            Finding("creds", "jdoe", tags: new[] { "valid-credential" }),
            Edge("canpsremote", "jdoe", "WS01"),
            Edge("canrdp", "jdoe", "WS02"),
            Edge("executedcom", "jdoe", "WS03"));

        _sut.Evaluate(corpus).Select(p => p.Name)
            .Should().HaveCount(3);
    }
}
