using System.Text.Json;
using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Tools.Normalizers;

/// <summary>
/// Parses Slither's <c>--json</c> output for Solidity static-analysis findings. Maps
/// Slither's impact levels onto the engine's <see cref="Severity"/> scale so smart-contract
/// findings rank alongside AD and cloud paths.
/// </summary>
public sealed class SlitherNormalizer : INormalizer
{
    public string Source => "slither";

    public bool CanParse(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return false;
        }

        var trimmed = rawOutput.TrimStart();
        return trimmed.StartsWith('{')
            && trimmed.Contains("\"detectors\"", StringComparison.OrdinalIgnoreCase);
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
            if (!TryGetDetectors(doc.RootElement, out var detectors))
            {
                return findings;
            }

            foreach (var detector in detectors.EnumerateArray())
            {
                var check = GetString(detector, "check") ?? "unknown";
                var impact = GetString(detector, "impact") ?? "Informational";
                var confidence = GetString(detector, "confidence") ?? "Medium";
                var description = GetString(detector, "description")?.Trim();
                var contract = ResolveContract(detector);

                findings.Add(new Finding
                {
                    Title = $"Solidity: {check} ({impact})",
                    Domain = AssetDomain.SmartContract,
                    Severity = MapImpact(impact),
                    Confidence = MapConfidence(confidence),
                    Source = Source,
                    Principal = contract,
                    Tags = new[] { "smart-contract", check.ToLowerInvariant(), "static-analysis" },
                    Properties = new Dictionary<string, string>
                    {
                        ["check"] = check,
                        ["impact"] = impact,
                        ["slitherConfidence"] = confidence,
                    },
                    Evidence = description,
                });
            }
        }

        return findings.Select(f => f.WithComputedId()).ToList();
    }

    private static bool TryGetDetectors(JsonElement root, out JsonElement detectors)
    {
        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("results", out var results) &&
            results.ValueKind == JsonValueKind.Object &&
            results.TryGetProperty("detectors", out detectors) &&
            detectors.ValueKind == JsonValueKind.Array)
        {
            return true;
        }

        // Tolerate a top-level "detectors" array.
        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("detectors", out detectors) &&
            detectors.ValueKind == JsonValueKind.Array)
        {
            return true;
        }

        detectors = default;
        return false;
    }

    private static Severity MapImpact(string impact) => impact.ToLowerInvariant() switch
    {
        "high" => Severity.Critical,
        "medium" => Severity.High,
        "low" => Severity.Medium,
        "informational" => Severity.Low,
        "optimization" => Severity.Info,
        _ => Severity.Info,
    };

    private static Confidence MapConfidence(string confidence) => confidence.ToLowerInvariant() switch
    {
        "high" => Confidence.Confirmed,
        "medium" => Confidence.Probable,
        _ => Confidence.Suspected,
    };

    private static string? ResolveContract(JsonElement detector)
    {
        if (!detector.TryGetProperty("elements", out var elements) ||
            elements.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var element in elements.EnumerateArray())
        {
            var name = GetString(element, "name");
            if (name is not null)
            {
                return name;
            }
        }

        return null;
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;
}
