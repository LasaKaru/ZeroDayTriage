using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// Accounts with Kerberos pre-authentication disabled can be AS-REP roasted without any
/// prior credentials, making them an ideal initial foothold.
/// </summary>
public sealed class AsRepRoastRule : IAttackPathRule
{
    public string Id => "AD-ASREP";

    public string Description => "DONT_REQ_PREAUTH account -> AS-REP roast -> crack -> foothold.";

    public AssetDomain Domain => AssetDomain.ActiveDirectory;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        foreach (var f in findings.WithTag("asreproastable"))
        {
            if (string.IsNullOrWhiteSpace(f.Principal))
            {
                continue;
            }

            yield return new AttackPath
            {
                Name = $"AS-REP roast {f.Principal}",
                Objective = "Initial credential access",
                Domain = AssetDomain.ActiveDirectory,
                Phase = MissionPhase.InitialAccess,
                Impact = Severity.High,
                Confidence = f.Confidence,
                Rationale =
                    $"{f.Principal} does not require Kerberos pre-auth -> harvest the AS-REP and " +
                    "crack offline with no credentials required. Strong opening move.",
                Steps = new[]
                {
                    new AttackStep
                    {
                        Action = $"Roast {f.Principal}'s AS-REP and crack it offline.",
                        Tooling = $"GetNPUsers.py '<DOMAIN>/' -usersfile users.txt -no-pass  # targets {f.Principal}",
                        Phase = KillChainPhase.Exploit,
                        Technique = "T1558.004",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                },
            };
        }
    }
}
