using System.Globalization;
using System.Text.Json;
using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Tools.Normalizers;

/// <summary>
/// Parses RITA-style beacon-analysis JSON to surface encrypted C2 beaconing — the heart of the
/// Command &amp; Control phase. A high beacon score (regular interval, low jitter, many
/// connections) is exactly the "encrypted C2 beaconing traffic" the event asks you to trace.
/// </summary>
public sealed class BeaconAnalysisNormalizer : INormalizer
{
    public string Source => "rita";

    public bool CanParse(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return false;
        }

        var trimmed = rawOutput.TrimStart();
        return (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            && trimmed.Contains("\"beacon", StringComparison.OrdinalIgnoreCase)
            && trimmed.Contains("score", StringComparison.OrdinalIgnoreCase);
    }

    public IReadOnlyList<Finding> Parse(string rawOutput)
    {
        var findings = new List<Finding>();
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return findings;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(rawOutput);
        }
        catch (JsonException)
        {
            return findings;
        }

        using (doc)
        {
            if (!TryGetBeacons(doc.RootElement, out var beacons))
            {
                return findings;
            }

            foreach (var beacon in beacons.EnumerateArray())
            {
                var score = GetDouble(beacon, "score");
                if (score is null)
                {
                    continue;
                }

                var src = GetString(beacon, "source") ?? GetString(beacon, "src");
                var dst = GetString(beacon, "destination") ?? GetString(beacon, "dst");
                var connections = GetDouble(beacon, "connections");

                // RITA scores in [0,1]; treat >=0.8 as a confident beacon.
                var strong = score >= 0.8;

                findings.Add(new Finding
                {
                    Title = $"C2 beacon {src} -> {dst} (score {score:0.00})",
                    Domain = AssetDomain.Network,
                    Phase = MissionPhase.CommandAndControl,
                    Severity = strong ? Severity.Critical : Severity.High,
                    Confidence = strong ? Confidence.Confirmed : Confidence.Probable,
                    Source = Source,
                    Principal = src,
                    Technique = "T1071.001",
                    Tags = new[] { "c2-beacon", "network", strong ? "high-confidence" : "candidate" },
                    Properties = new Dictionary<string, string>
                    {
                        ["score"] = score.Value.ToString("0.000", CultureInfo.InvariantCulture),
                        ["source"] = src ?? "?",
                        ["destination"] = dst ?? "?",
                        ["connections"] = connections?.ToString("0", CultureInfo.InvariantCulture) ?? "?",
                    },
                    Evidence = beacon.GetRawText(),
                });
            }
        }

        return findings.Select(f => f.WithComputedId()).ToList();
    }

    private static bool TryGetBeacons(JsonElement root, out JsonElement beacons)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            beacons = root;
            return true;
        }

        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("beacons", out beacons) &&
            beacons.ValueKind == JsonValueKind.Array)
        {
            return true;
        }

        beacons = default;
        return false;
    }

    private static double? GetDouble(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var prop))
        {
            return null;
        }

        return prop.ValueKind switch
        {
            JsonValueKind.Number => prop.GetDouble(),
            JsonValueKind.String when double.TryParse(prop.GetString(), NumberStyles.Any, CultureInfo.InvariantCulture, out var d) => d,
            _ => null,
        };
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;
}
