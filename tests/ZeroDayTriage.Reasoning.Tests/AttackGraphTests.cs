using FluentAssertions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning.Graph;
using Xunit;
using static ZeroDayTriage.Reasoning.Tests.Builders;

namespace ZeroDayTriage.Reasoning.Tests;

public sealed class AttackGraphTests
{
    private static Finding Edge(string type, string from, string to) =>
        Finding($"{type}: {from}->{to}", from,
            properties: new Dictionary<string, string> { ["target"] = to },
            tags: new[] { type });

    [Fact]
    public void Builds_edges_only_from_recognized_edge_tags()
    {
        var graph = new AttackGraph(new[]
        {
            Edge("adminto", "jdoe", "ws01"),
            Finding("not an edge", "x", tags: "kerberoastable"),
        });

        graph.EdgeCount.Should().Be(1);
    }

    [Fact]
    public void Finds_multi_hop_shortest_path()
    {
        var graph = new AttackGraph(new[]
        {
            Edge("adminto", "jdoe", "ws01"),
            Edge("hassession", "ws01", "svc_adm"),
            Edge("memberof", "svc_adm", "domain admins"),
        });

        var path = graph.ShortestPath(new[] { "jdoe" }, n => n == "domain admins");

        path.Should().NotBeNull();
        path!.Select(h => h.To).Should().ContainInOrder("ws01", "svc_adm", "domain admins");
        path!.Select(h => h.EdgeType).Should().ContainInOrder("adminto", "hassession", "memberof");
    }

    [Fact]
    public void Returns_null_when_goal_unreachable()
    {
        var graph = new AttackGraph(new[] { Edge("adminto", "jdoe", "ws01") });

        graph.ShortestPath(new[] { "jdoe" }, n => n == "domain admins").Should().BeNull();
    }

    [Fact]
    public void Prefers_the_lower_cost_route()
    {
        // jdoe can reach DA directly via GenericAll (cost 1.0) or the long way via two hops.
        var graph = new AttackGraph(new[]
        {
            Edge("genericall", "jdoe", "domain admins"),
            Edge("canrdp", "jdoe", "ws01"),
            Edge("genericall", "ws01", "domain admins"),
        });

        var path = graph.ShortestPath(new[] { "jdoe" }, n => n == "domain admins");

        path!.Should().HaveCount(1);
        path![0].EdgeType.Should().Be("genericall");
    }

    [Fact]
    public void Normalizes_principals_so_domain_qualified_names_match()
    {
        var graph = new AttackGraph(new[] { Edge("adminto", "EVILCORP\\jdoe", "ws01") });

        var path = graph.ShortestPath(new[] { "jdoe@evilcorp.local" }, n => n == "ws01");

        path.Should().NotBeNull();
    }

    [Fact]
    public void Ignores_self_loops()
    {
        var graph = new AttackGraph(new[] { Edge("genericall", "jdoe", "jdoe") });

        graph.EdgeCount.Should().Be(0);
    }
}
