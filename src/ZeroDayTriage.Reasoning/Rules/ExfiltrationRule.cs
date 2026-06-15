using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// Phase 5 — Data Exfiltration. An exfiltration alert (bulk upload, DNS tunneling) becomes the
/// path to identify exactly which backend database or financial records left the building and to
/// contain the channel. When a C2 channel is also known, the rule notes that exfil likely rode it.
/// </summary>
public sealed class ExfiltrationRule : IAttackPathRule
{
    public string Id => "EC-EXFIL";

    public string Description => "Exfil alert -> identify targeted DB/records -> contain channel.";

    public AssetDomain Domain => AssetDomain.Network;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        var c2Present = findings.HasTag("c2-beacon") || findings.HasTag("c2-infra");

        foreach (var f in findings.WithTag("exfiltration"))
        {
            var src = f.Property("src_ip") ?? f.Principal ?? "the source host";
            var dst = f.Property("dest_ip") ?? "the external endpoint";

            yield return new AttackPath
            {
                Name = $"Exfiltration {src} -> {dst}",
                Objective = "Identify the targeted records and contain the channel",
                Domain = AssetDomain.Network,
                Phase = MissionPhase.DataExfiltration,
                Impact = Severity.Critical,
                Confidence = f.Confidence,
                Rationale = c2Present
                    ? $"Outbound data theft from {src} aligns with the known C2 channel -> identify the database " +
                      "objects accessed before the transfer and cut egress."
                    : $"Outbound data theft from {src} to {dst} -> identify the database objects accessed before " +
                      "the transfer and cut egress.",
                Steps = new[]
                {
                    new AttackStep
                    {
                        Action = $"Correlate {src}'s DB access logs in the window before the transfer.",
                        Tooling = "Join SQL audit / file-access logs to the exfil timestamp to name the records.",
                        Phase = KillChainPhase.Identify,
                        Technique = "T1005",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                    new AttackStep
                    {
                        Action = $"Contain the channel to {dst} and quantify what left.",
                        Tooling = "Block egress to the destination; size the transfer from flow records.",
                        Phase = KillChainPhase.LootAndPivot,
                        Technique = "T1041",
                        EvidenceFindingIds = new[] { f.Id },
                    },
                },
            };
        }
    }
}
