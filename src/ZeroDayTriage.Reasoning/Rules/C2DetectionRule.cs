using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// Phase 2 — Command &amp; Control Evasion. Correlates beacon-analysis hits and IDS C2 signatures
/// for the same host into one response path: trace the encrypted channel, extract the C2
/// infrastructure as IOCs, and block/scope it. When malware triage has already yielded the C2
/// endpoints, the rule fuses them in for confirmation.
/// </summary>
public sealed class C2DetectionRule : IAttackPathRule
{
    public string Id => "EC-C2";

    public string Description => "Beaconing + C2 signatures -> trace channel, extract & block IOCs.";

    public AssetDomain Domain => AssetDomain.Network;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        var beacons = findings.WithTag("c2-beacon")
            .Concat(findings.WithTag("c2-infra"))
            .GroupBy(f => f.Id)
            .Select(g => g.First())
            .ToList();

        foreach (var beacon in beacons)
        {
            var src = beacon.Property("source") ?? beacon.Property("src_ip") ?? beacon.Principal ?? "host";
            var dst = beacon.Property("destination") ?? beacon.Property("endpoint")
                ?? beacon.Property("dest_ip") ?? "the C2";

            var evidence = new List<string> { beacon.Id };
            var knownInfra = findings.WithTag("c2-infra").FirstOrDefault();
            if (knownInfra is not null && knownInfra.Id != beacon.Id)
            {
                evidence.Add(knownInfra.Id);
            }

            yield return new AttackPath
            {
                Name = $"Trace C2 channel {src} -> {dst}",
                Objective = "Identify and contain the C2 channel",
                Domain = AssetDomain.Network,
                Phase = MissionPhase.CommandAndControl,
                Impact = beacon.Severity,
                Confidence = beacon.Confidence,
                Rationale =
                    $"{src} shows encrypted C2 beaconing toward {dst} -> trace the channel, extract the " +
                    "infrastructure as IOCs, and scope every host talking to it.",
                Steps = new[]
                {
                    new AttackStep
                    {
                        Action = $"Reconstruct the {src} -> {dst} sessions and confirm periodicity/jitter.",
                        Tooling = "zeek-cut / RITA show-beacons; inspect JA3/JARM of the TLS sessions.",
                        Phase = KillChainPhase.Identify,
                        Technique = "T1071.001",
                        EvidenceFindingIds = evidence,
                    },
                    new AttackStep
                    {
                        Action = $"Extract {dst} as an IOC and find every other host beaconing to it.",
                        Tooling = "Hunt the dest across flow logs; block at egress; tag compromised hosts.",
                        Phase = KillChainPhase.LootAndPivot,
                        Technique = "T1071",
                        EvidenceFindingIds = evidence,
                    },
                },
            };
        }
    }
}
