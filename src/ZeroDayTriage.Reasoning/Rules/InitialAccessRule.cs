using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// Phase 1 — Initial Intrusion. A weaponized "update" dropper (SocGholish-style) or drive-by
/// alert marks the foothold. The path tells the operator/investigator to scope the patient
/// zero host and hunt for the second-stage payload that follows.
/// </summary>
public sealed class InitialAccessRule : IAttackPathRule
{
    public string Id => "EC-INITIAL-ACCESS";

    public string Description => "Fake-update / drive-by dropper -> foothold -> hunt second stage.";

    public AssetDomain Domain => AssetDomain.Network;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        foreach (var f in findings.WithTag("initial-access"))
        {
            var host = f.Property("src_ip") ?? f.Principal ?? "patient-zero";

            yield return new AttackPath
            {
                Name = $"Initial access via {f.Title}",
                Objective = "Establish/confirm foothold and find the second stage",
                Domain = AssetDomain.Network,
                Phase = MissionPhase.InitialAccess,
                Impact = f.Severity,
                Confidence = f.Confidence,
                Rationale =
                    $"Drive-by / fake-update activity from {host} marks patient zero -> isolate the host, " +
                    "pull the dropped payload, and pivot to the C2 it reaches out to.",
                Steps = new[]
                {
                    new AttackStep
                    {
                        Action = $"Scope patient-zero host {host} and capture the dropped payload.",
                        Tooling = "Triage the EDR timeline / collect %TEMP% JS + spawned process tree.",
                        Phase = KillChainPhase.Identify,
                        Technique = "T1189",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                    new AttackStep
                    {
                        Action = "Correlate with beaconing to identify the C2 channel established next.",
                        Tooling = "Pivot to RITA/Suricata findings for the same source host.",
                        Phase = KillChainPhase.LootAndPivot,
                        Technique = "T1071",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                },
            };
        }
    }
}
