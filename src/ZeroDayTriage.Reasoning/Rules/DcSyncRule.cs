using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// Phase 3 depth — when a principal already holds replication rights (GetChanges/GetChangesAll),
/// DCSync is a direct route to krbtgt and a golden ticket: full domain persistence. This is the
/// "workstation -> Domain Controller" terminus the event describes.
/// </summary>
public sealed class DcSyncRule : IAttackPathRule
{
    public string Id => "AD-DCSYNC";

    public string Description => "DCSync rights -> dump krbtgt -> golden ticket / domain persistence.";

    public AssetDomain Domain => AssetDomain.ActiveDirectory;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        foreach (var f in findings.WithTag("dcsync"))
        {
            var principal = f.Principal ?? f.Property("target") ?? "the principal";

            yield return new AttackPath
            {
                Name = $"DCSync via {principal}",
                Objective = "Domain Admin / krbtgt — full domain compromise",
                Domain = AssetDomain.ActiveDirectory,
                Phase = MissionPhase.PrivilegeEscalation,
                Impact = Severity.Critical,
                Confidence = f.Confidence,
                Rationale =
                    $"{principal} holds replication rights -> DCSync krbtgt and forge a golden ticket for " +
                    "durable Domain Admin. Terminal privilege-escalation objective.",
                Steps = new[]
                {
                    new AttackStep
                    {
                        Action = $"Replicate domain secrets using {principal}'s rights.",
                        Tooling = "secretsdump.py -just-dc-ntlm <DOMAIN>/<principal>@<DC>",
                        Phase = KillChainPhase.LootAndPivot,
                        Technique = "T1003.006",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                    new AttackStep
                    {
                        Action = "Forge a golden ticket from the krbtgt hash for persistence.",
                        Tooling = "ticketer.py -nthash <krbtgt> -domain-sid <SID> -domain <DOMAIN> Administrator",
                        Phase = KillChainPhase.LootAndPivot,
                        Technique = "T1558.001",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                },
            };
        }
    }
}
