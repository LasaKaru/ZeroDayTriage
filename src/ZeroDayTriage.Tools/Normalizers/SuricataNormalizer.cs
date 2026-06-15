using System.Text.Json;
using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Tools.Normalizers;

/// <summary>
/// Parses Suricata EVE NDJSON (one JSON object per line) and classifies each IDS alert into
/// the EVIL CORP kill-chain phase its signature implies: SocGholish / fake-update droppers
/// (Initial Access), Cobalt Strike / Dridex beaconing (C2), and bulk upload / DNS tunneling
/// (Exfiltration). This single sensor feed therefore lights up three of the five phases.
/// </summary>
public sealed class SuricataNormalizer : INormalizer
{
    public string Source => "suricata";

    private static readonly (MissionPhase Phase, string Tag, string[] Keywords)[] Classifiers =
    {
        (MissionPhase.InitialAccess, "initial-access", new[]
        {
            "socgholish", "fake update", "fakeupdate", "fake browser", "drive-by", "exploit kit", "rig ek",
        }),
        (MissionPhase.CommandAndControl, "c2-beacon", new[]
        {
            "cobalt strike", "cobaltstrike", "beacon", "dridex", "empire", "cnc", "c2", "check-in", "checkin",
        }),
        (MissionPhase.DataExfiltration, "exfiltration", new[]
        {
            "exfil", "exfiltration", "dns tunnel", "data theft", "large outbound", "upload to",
        }),
    };

    public bool CanParse(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return false;
        }

        foreach (var line in EnumerateLines(rawOutput))
        {
            if (line.Contains("\"event_type\"", StringComparison.OrdinalIgnoreCase) &&
                line.Contains("\"alert\"", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public IReadOnlyList<Finding> Parse(string rawOutput)
    {
        var findings = new List<Finding>();
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return findings;
        }

        foreach (var line in EnumerateLines(rawOutput))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed[0] != '{')
            {
                continue;
            }

            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(trimmed);
            }
            catch (JsonException)
            {
                continue;
            }

            using (doc)
            {
                var root = doc.RootElement;
                if (GetString(root, "event_type") is not "alert" ||
                    !root.TryGetProperty("alert", out var alert))
                {
                    continue;
                }

                var signature = GetString(alert, "signature") ?? "Unknown alert";
                var (phase, tag) = Classify(signature);
                var severity = MapSeverity(alert);
                var src = GetString(root, "src_ip");
                var dest = GetString(root, "dest_ip");

                findings.Add(new Finding
                {
                    Title = signature,
                    Domain = AssetDomain.Network,
                    Phase = phase,
                    Severity = severity,
                    Confidence = Confidence.Probable,
                    Source = Source,
                    Principal = src,
                    Technique = TechniqueFor(phase),
                    Tags = new[] { tag, "ids", "network" },
                    Properties = BuildProperties(src, dest, signature),
                    Evidence = trimmed,
                });
            }
        }

        return findings.Select(f => f.WithComputedId()).ToList();
    }

    private static (MissionPhase, string) Classify(string signature)
    {
        var lowered = signature.ToLowerInvariant();
        foreach (var (phase, tag, keywords) in Classifiers)
        {
            if (keywords.Any(k => lowered.Contains(k, StringComparison.Ordinal)))
            {
                return (phase, tag);
            }
        }

        // Default unmatched malware alerts to C2 — they are post-foothold by nature.
        return (MissionPhase.CommandAndControl, "c2-beacon");
    }

    private static string TechniqueFor(MissionPhase phase) => phase switch
    {
        MissionPhase.InitialAccess => "T1189",       // Drive-by Compromise
        MissionPhase.CommandAndControl => "T1071",   // Application Layer Protocol
        MissionPhase.DataExfiltration => "T1041",    // Exfiltration Over C2 Channel
        _ => "T1071",
    };

    private static Severity MapSeverity(JsonElement alert)
    {
        // Suricata severity is 1 (most severe) .. 3 (least).
        if (alert.TryGetProperty("severity", out var sev) && sev.ValueKind == JsonValueKind.Number)
        {
            return sev.GetInt32() switch
            {
                1 => Severity.Critical,
                2 => Severity.High,
                _ => Severity.Medium,
            };
        }

        return Severity.High;
    }

    private static Dictionary<string, string> BuildProperties(string? src, string? dest, string signature)
    {
        var props = new Dictionary<string, string> { ["signature"] = signature };
        if (src is not null)
        {
            props["src_ip"] = src;
        }

        if (dest is not null)
        {
            props["dest_ip"] = dest;
        }

        return props;
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;

    private static IEnumerable<string> EnumerateLines(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
}
