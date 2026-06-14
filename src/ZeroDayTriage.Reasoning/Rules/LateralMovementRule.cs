using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// Explicit lateral-movement reasoning: when an owned principal (we have its credentials) also
/// has an execution edge — local admin, PSRemote, RDP, or DCOM — onto a computer, that is a
/// direct hop to a new host where fresh credentials and sessions can be harvested.
/// </summary>
public sealed class LateralMovementRule : IAttackPathRule
{
    private static readonly (string Tag, string Verb, string Tooling, string Technique)[] ExecEdges =
    {
        ("adminto", "is local admin on", "nxc smb {0} -u {1} -p <secret> --sam --lsa", "T1021.002"),
        ("canpsremote", "can PSRemote to", "evil-winrm -i {0} -u {1} -p <secret>", "T1021.006"),
        ("canrdp", "can RDP to", "xfreerdp /v:{0} /u:{1} /p:<secret>", "T1021.001"),
        ("executedcom", "can ExecuteDCOM on", "impacket-dcomexec {1}:<secret>@{0}", "T1021.003"),
    };

    public string Id => "AD-LATERAL";

    public string Description => "Owned principal with an execution edge -> move to a new host.";

    public AssetDomain Domain => AssetDomain.ActiveDirectory;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        var owned = findings.WithTag("valid-credential")
            .Concat(findings.WithTag("pass-the-hash"))
            .Where(f => !string.IsNullOrWhiteSpace(f.Principal))
            .Select(f => FindingCorpus.Normalize(f.Principal!))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (owned.Count == 0)
        {
            yield break;
        }

        foreach (var (tag, verb, tooling, technique) in ExecEdges)
        {
            foreach (var edge in findings.WithTag(tag))
            {
                if (string.IsNullOrWhiteSpace(edge.Principal))
                {
                    continue;
                }

                var source = FindingCorpus.Normalize(edge.Principal);
                if (!owned.Contains(source))
                {
                    continue;
                }

                var target = edge.Property("target") ?? "the host";

                yield return new AttackPath
                {
                    Name = $"Lateral movement: {edge.Principal} -> {target}",
                    Objective = "Pivot to a new host and harvest credentials",
                    Domain = AssetDomain.ActiveDirectory,
                    Phase = MissionPhase.PrivilegeEscalation,
                    Impact = Severity.High,
                    Confidence = Confidence.Confirmed,
                    Rationale =
                        $"We hold {edge.Principal}'s credentials and it {verb} {target} -> move there, then dump " +
                        "fresh credentials and logged-on sessions to continue the chain.",
                    Steps = new[]
                    {
                        new AttackStep
                        {
                            Action = $"Authenticate to {target} as {edge.Principal} and execute.",
                            Tooling = string.Format(tooling, target, edge.Principal),
                            Phase = KillChainPhase.LootAndPivot,
                            Technique = technique,
                            EvidenceFindingIds = new[] { edge.Id },
                        },
                    },
                };
            }
        }
    }
}
