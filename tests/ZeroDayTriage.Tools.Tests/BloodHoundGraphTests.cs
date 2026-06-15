using FluentAssertions;
using ZeroDayTriage.Tools.Normalizers;
using Xunit;

namespace ZeroDayTriage.Tools.Tests;

public sealed class BloodHoundGraphTests
{
    private readonly BloodHoundNormalizer _sut = new();

    [Fact]
    public void Extracts_group_membership_edges()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundGroups);

        findings.Should().Contain(f =>
            f.HasTag("memberof") &&
            f.Principal!.Contains("SVC_ADM") &&
            f.Property("target")!.Contains("DOMAIN ADMINS"));
    }

    [Fact]
    public void Flags_high_value_groups()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundGroups);

        findings.Should().Contain(f => f.HasTag("highvalue") && f.Principal!.Contains("DOMAIN ADMINS"));
    }

    [Fact]
    public void Extracts_adminto_edges_from_local_admins()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundComputersGraph);

        findings.Should().Contain(f =>
            f.HasTag("adminto") &&
            f.Principal!.Contains("JDOE") &&
            f.Property("target")!.Contains("WS01"));
    }

    [Fact]
    public void Extracts_rdp_edges()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundComputersGraph);

        findings.Should().Contain(f => f.HasTag("canrdp") && f.Principal!.Contains("HELPDESK"));
    }

    [Fact]
    public void Extracts_session_edges_with_computer_as_source()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundComputersGraph);

        // HasSession is computer -> user: controlling the computer yields the user's creds.
        findings.Should().Contain(f =>
            f.HasTag("hassession") &&
            f.Principal!.Contains("WS01") &&
            f.Property("target")!.Contains("SVC_ADM"));
    }

    [Fact]
    public void Graph_edges_carry_edge_tag_and_target_property()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundComputersGraph);

        findings.Where(f => f.HasTag("graph-edge"))
            .Should().OnlyContain(f => f.Property("target") != null && f.Property("edge") != null);
    }
}
