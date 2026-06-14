using System.Text.Json;
using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Tools.Normalizers;

/// <summary>
/// Parses Certipy "find" JSON output and surfaces vulnerable certificate templates
/// (ESC1–ESC8). AD CS abuse is one of the most common — and most decisive — paths in
/// modern AD CTFs, so every flagged ESC vulnerability becomes a Critical finding.
/// </summary>
public sealed class CertipyNormalizer : INormalizer
{
    public string Source => "certipy";

    public bool CanParse(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return false;
        }

        var trimmed = rawOutput.TrimStart();
        return trimmed.StartsWith('{')
            && trimmed.Contains("Certificate Templates", StringComparison.OrdinalIgnoreCase);
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
            if (!TryFindTemplates(doc.RootElement, out var templates))
            {
                return findings;
            }

            foreach (var template in templates.EnumerateObject())
            {
                ParseTemplate(template.Value, findings);
            }
        }

        return findings.Select(f => f.WithComputedId()).ToList();
    }

    private void ParseTemplate(JsonElement template, List<Finding> findings)
    {
        if (template.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        var templateName = GetString(template, "Template Name")
            ?? GetString(template, "Name")
            ?? "<unknown template>";

        if (!TryFindVulnerabilities(template, out var vulns))
        {
            return;
        }

        foreach (var vuln in vulns.EnumerateObject())
        {
            var esc = vuln.Name.Trim();
            var detail = vuln.Value.ValueKind == JsonValueKind.String
                ? vuln.Value.GetString()
                : vuln.Value.ToString();

            findings.Add(new Finding
            {
                Title = $"AD CS {esc} on template {templateName}",
                Domain = AssetDomain.ActiveDirectory,
                Severity = Severity.Critical,
                Confidence = Confidence.Confirmed,
                Source = Source,
                Principal = templateName,
                Technique = "T1649",
                Tags = new[] { "adcs", esc.ToLowerInvariant(), "privilege-escalation", "ad" },
                Properties = new Dictionary<string, string>
                {
                    ["template"] = templateName,
                    ["esc"] = esc,
                },
                Evidence = detail,
            });
        }
    }

    private static bool TryFindTemplates(JsonElement root, out JsonElement templates)
    {
        // Certipy nests under "Certificate Templates"; tolerate a top-level object too.
        foreach (var name in new[] { "Certificate Templates", "Certificate Authorities" })
        {
            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty(name, out templates) &&
                templates.ValueKind == JsonValueKind.Object)
            {
                return true;
            }
        }

        templates = default;
        return false;
    }

    private static bool TryFindVulnerabilities(JsonElement template, out JsonElement vulns)
    {
        foreach (var prop in template.EnumerateObject())
        {
            // Certipy labels this key "[!] Vulnerabilities" or "Vulnerabilities".
            if (prop.Name.Contains("Vulnerabilities", StringComparison.OrdinalIgnoreCase) &&
                prop.Value.ValueKind == JsonValueKind.Object)
            {
                vulns = prop.Value;
                return true;
            }
        }

        vulns = default;
        return false;
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;
}
