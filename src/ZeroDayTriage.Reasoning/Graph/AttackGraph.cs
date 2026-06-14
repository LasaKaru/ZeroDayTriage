using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Graph;

/// <summary>A directed edge in the attack graph: controlling <see cref="Source"/> lets you reach/control <see cref="Target"/>.</summary>
public sealed record GraphEdge(string Source, string Target, string Type, string FindingId, double Cost);

/// <summary>One hop of a resolved shortest path.</summary>
public sealed record PathHop(string From, string To, string EdgeType, string FindingId);

/// <summary>
/// The BloodHound-style attack graph. Nodes are normalized principal names; edges are the
/// control relationships (ACL rights, AdminTo, sessions, RDP/PSRemote/DCOM, group membership).
/// Provides the signature capability: the shortest path from an owned foothold to a high-value
/// target such as Domain Admins.
/// </summary>
public sealed class AttackGraph
{
    /// <summary>Tags that represent a traversable control edge, mapped to a traversal cost.</summary>
    private static readonly IReadOnlyDictionary<string, double> EdgeCosts = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
    {
        ["memberof"] = 0.5,            // membership is free-ish to leverage
        ["genericall"] = 1.0,
        ["genericwrite"] = 1.0,
        ["writedacl"] = 1.0,
        ["writeowner"] = 1.0,
        ["owns"] = 1.0,
        ["forcechangepassword"] = 1.0,
        ["addmember"] = 1.0,
        ["adminto"] = 1.0,
        ["canpsremote"] = 1.0,
        ["canrdp"] = 1.2,
        ["executedcom"] = 1.2,
        ["hassession"] = 1.5,          // requires the user to be logged on
        ["dcsync"] = 1.0,
    };

    private readonly Dictionary<string, List<GraphEdge>> _adjacency = new(StringComparer.OrdinalIgnoreCase);

    public AttackGraph(IEnumerable<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        foreach (var finding in findings)
        {
            var type = finding.Tags.FirstOrDefault(t => EdgeCosts.ContainsKey(t));
            if (type is null)
            {
                continue;
            }

            var target = finding.Property("target");
            if (string.IsNullOrWhiteSpace(finding.Principal) || string.IsNullOrWhiteSpace(target))
            {
                continue;
            }

            var source = FindingCorpus.Normalize(finding.Principal);
            var dest = FindingCorpus.Normalize(target);
            if (source == dest)
            {
                continue;
            }

            AddEdge(new GraphEdge(source, dest, type, finding.Id, EdgeCosts[type]));
        }
    }

    public int EdgeCount => _adjacency.Values.Sum(v => v.Count);

    public IReadOnlyCollection<string> Nodes
    {
        get
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (from, edges) in _adjacency)
            {
                set.Add(from);
                foreach (var e in edges)
                {
                    set.Add(e.Target);
                }
            }

            return set;
        }
    }

    /// <summary>
    /// Lowest-cost path from any of <paramref name="sources"/> to any node satisfying
    /// <paramref name="isGoal"/>, using Dijkstra over the edge costs. Returns null when no
    /// owned principal can reach a goal.
    /// </summary>
    public IReadOnlyList<PathHop>? ShortestPath(IEnumerable<string> sources, Func<string, bool> isGoal)
    {
        ArgumentNullException.ThrowIfNull(sources);
        ArgumentNullException.ThrowIfNull(isGoal);

        var seeds = sources
            .Select(FindingCorpus.Normalize)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (seeds.Count == 0)
        {
            return null;
        }

        // A seed that is already a goal is a zero-hop win; the caller handles that case, so we
        // only search for goals reachable via at least one edge.
        var dist = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        var prev = new Dictionary<string, (string Node, GraphEdge Edge)>(StringComparer.OrdinalIgnoreCase);
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Simple priority queue via SortedSet keyed on (cost, node).
        var frontier = new SortedSet<(double Cost, string Node)>(Comparer<(double Cost, string Node)>.Create(
            (a, b) => a.Cost != b.Cost ? a.Cost.CompareTo(b.Cost) : string.CompareOrdinal(a.Node, b.Node)));

        foreach (var seed in seeds)
        {
            dist[seed] = 0;
            frontier.Add((0, seed));
        }

        while (frontier.Count > 0)
        {
            var (cost, node) = frontier.Min;
            frontier.Remove(frontier.Min);
            if (!visited.Add(node))
            {
                continue;
            }

            // Goal reached via at least one edge (a seed itself is excluded by the prev check).
            if (isGoal(node) && prev.ContainsKey(node))
            {
                return Reconstruct(prev, node);
            }

            if (!_adjacency.TryGetValue(node, out var edges))
            {
                continue;
            }

            foreach (var edge in edges)
            {
                var newCost = cost + edge.Cost;
                if (!dist.TryGetValue(edge.Target, out var existing) || newCost < existing)
                {
                    dist[edge.Target] = newCost;
                    prev[edge.Target] = (node, edge);
                    frontier.Add((newCost, edge.Target));
                }
            }
        }

        return null;
    }

    private static IReadOnlyList<PathHop> Reconstruct(
        IReadOnlyDictionary<string, (string Node, GraphEdge Edge)> prev,
        string goal)
    {
        var hops = new List<PathHop>();
        var current = goal;
        while (prev.TryGetValue(current, out var step))
        {
            hops.Add(new PathHop(step.Node, current, step.Edge.Type, step.Edge.FindingId));
            current = step.Node;
        }

        hops.Reverse();
        return hops;
    }

    private void AddEdge(GraphEdge edge)
    {
        if (!_adjacency.TryGetValue(edge.Source, out var list))
        {
            list = new List<GraphEdge>();
            _adjacency[edge.Source] = list;
        }

        list.Add(edge);
    }
}
