using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// A captured NTLM hash with confirmed validity enables pass-the-hash lateral movement.
/// Local-admin context promotes the path to Critical and points at credential dumping.
/// </summary>
public sealed class PassTheHashRule : IAttackPathRule
{
    public string Id => "AD-PTH";

    public string Description => "Valid NTLM hash -> pass-the-hash -> lateral movement / dump.";

    public AssetDomain Domain => AssetDomain.ActiveDirectory;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        foreach (var f in findings.WithTag("pass-the-hash"))
        {
            var principal = f.Principal ?? "<user>";
            var host = f.Property("host") ?? "<host>";
            var isAdmin = f.HasTag("local-admin");

            var steps = new List<AttackStep>
            {
                new()
                {
                    Action = $"Pass {principal}'s NTLM hash to authenticate against {host}.",
                    Tooling = $"nxc smb {host} -u {principal} -H <NTLM>",
                    Phase = KillChainPhase.LootAndPivot,
                    Technique = "T1550.002",
                    EvidenceFindingIds = new[] { f.Id },
                },
            };

            if (isAdmin)
            {
                steps.Add(new AttackStep
                {
                    Action = $"With local admin on {host}, dump SAM/LSA secrets for further creds.",
                    Tooling = $"nxc smb {host} -u {principal} -H <NTLM> --sam --lsa",
                    Phase = KillChainPhase.LootAndPivot,
                    Technique = "T1003",
                    EvidenceFindingIds = new[] { f.Id },
                });
            }

            yield return new AttackPath
            {
                Name = $"Pass-the-hash {principal} -> {host}",
                Objective = isAdmin ? "Lateral movement + credential dumping" : "Lateral movement",
                Domain = AssetDomain.ActiveDirectory,
                Impact = isAdmin ? Severity.Critical : Severity.High,
                Confidence = f.Confidence,
                Rationale = isAdmin
                    ? $"{principal}'s hash grants local admin on {host} -> dump more secrets and snowball."
                    : $"{principal}'s NTLM hash is valid on {host} -> move laterally without cracking.",
                Steps = steps,
            };
        }
    }
}
