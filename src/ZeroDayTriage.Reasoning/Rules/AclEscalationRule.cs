using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// Dangerous ACEs (GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, ForceChangePassword)
/// let the holder take over the target principal. When the target itself carries DCSync rights
/// or is a high-value object, the rule notes the onward escalation.
/// </summary>
public sealed class AclEscalationRule : IAttackPathRule
{
    private static readonly string[] AbusableAceTags =
    {
        "genericall", "genericwrite", "writedacl", "writeowner", "owns", "forcechangepassword",
    };

    public string Id => "AD-ACL";

    public string Description => "Abusable ACE over a principal -> take over -> onward escalation.";

    public AssetDomain Domain => AssetDomain.ActiveDirectory;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        var seen = new HashSet<string>();

        foreach (var tag in AbusableAceTags)
        {
            foreach (var ace in findings.WithTag(tag))
            {
                if (!seen.Add(ace.Id))
                {
                    continue;
                }

                var holder = ace.Principal ?? "<principal>";
                var target = ace.Property("target") ?? "<target>";
                var right = ace.Property("right") ?? tag;

                var leadsToDcSync = findings.ForPrincipal(target).Any(f => f.HasTag("dcsync"));
                var impact = leadsToDcSync ? Severity.Critical : ace.Severity;

                var steps = new List<AttackStep>
                {
                    new()
                    {
                        Action = $"Abuse {right} held by {holder} to control {target}.",
                        Tooling = SuggestTooling(tag, target),
                        Phase = KillChainPhase.Exploit,
                        Technique = ace.Technique,
                        EvidenceFindingIds = new[] { ace.Id },
                    },
                };

                var rationale = $"{holder} has {right} over {target}; seize the object to inherit its access.";
                if (leadsToDcSync)
                {
                    steps.Add(new AttackStep
                    {
                        Action = $"{target} holds DCSync rights -> replicate the domain secrets.",
                        Tooling = "secretsdump.py -just-dc <DOMAIN>/<target>@<DC>",
                        Phase = KillChainPhase.LootAndPivot,
                        Technique = "T1003.006",
                    });
                    rationale =
                        $"{holder} --{right}--> {target}, and {target} can DCSync -> chain to full domain compromise.";
                }

                yield return new AttackPath
                {
                    Name = $"{right} over {target}",
                    Objective = leadsToDcSync ? "Domain compromise via ACL chain" : "Principal takeover",
                    Domain = AssetDomain.ActiveDirectory,
                    Impact = impact,
                    Confidence = ace.Confidence,
                    Rationale = rationale,
                    Steps = steps,
                };
            }
        }
    }

    private static string SuggestTooling(string tag, string target) => tag switch
    {
        "forcechangepassword" => $"net rpc password {target} -U ... / Set-DomainUserPassword",
        "genericwrite" => $"targetedKerberoast / Set-DomainObject -Identity {target} (write SPN or logon script)",
        "writedacl" => $"dacledit.py -principal <me> -target {target} -action write -rights FullControl",
        "writeowner" or "owns" => $"owneredit.py -action write -new-owner <me> -target {target}",
        _ => $"bloodyAD --host <DC> -d <DOMAIN> -u <me> -p <pw> add genericAll {target} <me>",
    };
}
