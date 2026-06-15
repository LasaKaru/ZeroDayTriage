using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// Kerberoastable service accounts become a path: request the SPN ticket, crack it offline,
/// then authenticate. When the same principal also holds a dangerous ACL or local-admin
/// rights elsewhere, the rule fuses those into a single higher-value chain — this is the
/// "roast then abuse GenericWrite" reasoning the plan calls out by name.
/// </summary>
public sealed class KerberoastingRule : IAttackPathRule
{
    public string Id => "AD-KERBEROAST";

    public string Description => "Kerberoastable SPN -> crack -> authenticate (-> abuse ACL / admin).";

    public AssetDomain Domain => AssetDomain.ActiveDirectory;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        foreach (var roastable in findings.WithTag("kerberoastable"))
        {
            var principal = roastable.Principal;
            if (string.IsNullOrWhiteSpace(principal))
            {
                continue;
            }

            var steps = new List<AttackStep>
            {
                new()
                {
                    Action = $"Request the service ticket for {principal} and crack it offline.",
                    Tooling = $"GetUserSPNs.py -request -dc-ip <DC> '<DOMAIN>/<USER>:<PASS>'  # or Rubeus kerberoast /user:{principal}",
                    Phase = KillChainPhase.Exploit,
                    Technique = "T1558.003",
                    EvidenceFindingIds = new[] { roastable.Id },
                },
                new()
                {
                    Action = $"Authenticate as {principal} with the cracked password.",
                    Tooling = "nxc smb <DC> -u <USER> -p <CRACKED>",
                    Phase = KillChainPhase.LootAndPivot,
                    Technique = "T1078.002",
                    EvidenceFindingIds = new[] { roastable.Id },
                },
            };

            var impact = Severity.High;
            var rationale =
                $"{principal} exposes a crackable SPN ticket; service accounts are frequently " +
                "over-privileged.";

            // Fuse with any escalation primitive owned by the same principal.
            var escalation = findings.ForPrincipal(principal).FirstOrDefault(f =>
                f.HasTag("genericwrite") || f.HasTag("genericall") ||
                f.HasTag("writedacl") || f.HasTag("local-admin") || f.HasTag("dcsync"));

            if (escalation is not null)
            {
                impact = Severity.Critical;
                var target = escalation.Property("target") ?? escalation.Property("host") ?? "the target";
                steps.Add(new AttackStep
                {
                    Action = $"Leverage {principal}'s {DescribeRight(escalation)} over {target}.",
                    Tooling = "bloodyAD / Set-DomainObjectOwner / dacledit.py to abuse the ACE.",
                    Phase = KillChainPhase.Exploit,
                    Technique = escalation.Technique,
                    EvidenceFindingIds = new[] { escalation.Id },
                });
                rationale =
                    $"{principal} is Kerberoastable AND holds {DescribeRight(escalation)} over {target} " +
                    "-> roast, crack, then take over the target. Highest-value fused chain.";
            }

            yield return new AttackPath
            {
                Name = $"Kerberoast {principal}",
                Objective = escalation is not null ? "Privilege escalation via roasted service account" : "Credential access",
                Domain = AssetDomain.ActiveDirectory,
                Impact = impact,
                Confidence = roastable.Confidence,
                Rationale = rationale,
                Steps = steps,
            };
        }
    }

    private static string DescribeRight(Finding finding)
    {
        if (finding.HasTag("dcsync")) return "DCSync rights";
        if (finding.HasTag("local-admin")) return "local administrator rights";
        if (finding.HasTag("genericall")) return "GenericAll";
        if (finding.HasTag("genericwrite")) return "GenericWrite";
        if (finding.HasTag("writedacl")) return "WriteDacl";
        return finding.Property("right") ?? "an abusable right";
    }
}
