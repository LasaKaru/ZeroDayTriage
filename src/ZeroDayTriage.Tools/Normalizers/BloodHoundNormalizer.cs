using System.Text.Json;
using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Tools.Normalizers;

/// <summary>
/// Parses SharpHound / BloodHound CE collection JSON (the per-object "users", "computers",
/// "groups" files) into findings. Extracts the high-value primitives the reasoning engine
/// cares about: Kerberoastable SPNs, AS-REP roastable accounts, unconstrained delegation,
/// and dangerous ACEs (GenericAll/GenericWrite/WriteDacl/Owns/DCSync).
/// </summary>
public sealed class BloodHoundNormalizer : INormalizer
{
    public string Source => "sharphound";

    public bool CanParse(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return false;
        }

        var trimmed = rawOutput.TrimStart();
        if (!trimmed.StartsWith('{'))
        {
            return false;
        }

        // BloodHound files carry a "meta" envelope with a "type" discriminator.
        return trimmed.Contains("\"meta\"", StringComparison.OrdinalIgnoreCase)
            && trimmed.Contains("\"data\"", StringComparison.OrdinalIgnoreCase);
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
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("data", out var data) ||
                data.ValueKind != JsonValueKind.Array)
            {
                return findings;
            }

            foreach (var node in data.EnumerateArray())
            {
                var name = ResolveName(node);
                if (name is null)
                {
                    continue;
                }

                ExtractAccountPrimitives(node, name, findings);
                ExtractAces(node, name, findings);
            }
        }

        return findings.Select(f => f.WithComputedId()).ToList();
    }

    private void ExtractAccountPrimitives(JsonElement node, string name, List<Finding> findings)
    {
        if (!node.TryGetProperty("Properties", out var props) || props.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        var enabled = !TryGetBool(props, "enabled", out var en) || en; // default true if absent

        if (TryGetBool(props, "hasspn", out var hasSpn) && hasSpn && enabled)
        {
            var spn = GetString(props, "serviceprincipalnames") ?? "service account";
            findings.Add(new Finding
            {
                Title = $"Kerberoastable account: {name}",
                Domain = AssetDomain.ActiveDirectory,
                Severity = Severity.High,
                Confidence = Confidence.Confirmed,
                Source = Source,
                Principal = name,
                Technique = "T1558.003",
                Tags = new[] { "kerberoastable", "ad", "credential-access" },
                Properties = new Dictionary<string, string> { ["spn"] = spn },
                Evidence = $"hasspn=true on {name}",
            });
        }

        if (TryGetBool(props, "dontreqpreauth", out var noPreauth) && noPreauth && enabled)
        {
            findings.Add(new Finding
            {
                Title = $"AS-REP roastable account: {name}",
                Domain = AssetDomain.ActiveDirectory,
                Severity = Severity.High,
                Confidence = Confidence.Confirmed,
                Source = Source,
                Principal = name,
                Technique = "T1558.004",
                Tags = new[] { "asreproastable", "ad", "credential-access" },
            });
        }

        if (TryGetBool(props, "unconstraineddelegation", out var unconstrained) && unconstrained)
        {
            findings.Add(new Finding
            {
                Title = $"Unconstrained delegation: {name}",
                Domain = AssetDomain.ActiveDirectory,
                Severity = Severity.Critical,
                Confidence = Confidence.Confirmed,
                Source = Source,
                Principal = name,
                Technique = "T1187",
                Tags = new[] { "unconstrained-delegation", "ad", "privilege-escalation" },
            });
        }
    }

    private void ExtractAces(JsonElement node, string name, List<Finding> findings)
    {
        if (!node.TryGetProperty("Aces", out var aces) || aces.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var ace in aces.EnumerateArray())
        {
            var right = GetString(ace, "RightName");
            var principal = GetString(ace, "PrincipalSID") ?? GetString(ace, "PrincipalName");
            if (right is null || principal is null)
            {
                continue;
            }

            var (tag, severity, technique) = ClassifyRight(right);
            if (tag is null)
            {
                continue;
            }

            findings.Add(new Finding
            {
                Title = $"{right} over {name}",
                Domain = AssetDomain.ActiveDirectory,
                Severity = severity,
                Confidence = Confidence.Confirmed,
                Source = Source,
                Principal = principal,
                Technique = technique,
                Tags = new[] { tag, "ad", "acl-abuse" },
                Properties = new Dictionary<string, string>
                {
                    ["target"] = name,
                    ["right"] = right,
                },
                Evidence = $"{principal} --{right}--> {name}",
            });
        }
    }

    private static (string? Tag, Severity Severity, string? Technique) ClassifyRight(string right) =>
        right.ToLowerInvariant() switch
        {
            "genericall" => ("genericall", Severity.High, "T1222"),
            "genericwrite" => ("genericwrite", Severity.High, "T1222"),
            "writedacl" => ("writedacl", Severity.High, "T1222"),
            "writeowner" => ("writeowner", Severity.High, "T1222"),
            "owns" => ("owns", Severity.High, "T1222"),
            "getchanges" => ("dcsync", Severity.Critical, "T1003.006"),
            "getchangesall" => ("dcsync", Severity.Critical, "T1003.006"),
            "addmember" => ("addmember", Severity.Medium, "T1098"),
            "forcechangepassword" => ("forcechangepassword", Severity.High, "T1098"),
            _ => (null, Severity.Info, null),
        };

    private static string? ResolveName(JsonElement node)
    {
        if (node.TryGetProperty("Properties", out var props) && props.ValueKind == JsonValueKind.Object)
        {
            var name = GetString(props, "name") ?? GetString(props, "samaccountname");
            if (name is not null)
            {
                return name;
            }
        }

        return GetString(node, "ObjectIdentifier");
    }

    private static bool TryGetBool(JsonElement element, string property, out bool value)
    {
        value = false;
        if (!element.TryGetProperty(property, out var prop))
        {
            return false;
        }

        switch (prop.ValueKind)
        {
            case JsonValueKind.True:
                value = true;
                return true;
            case JsonValueKind.False:
                value = false;
                return true;
            case JsonValueKind.String when bool.TryParse(prop.GetString(), out var parsed):
                value = parsed;
                return true;
            default:
                return false;
        }
    }

    private static string? GetString(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var prop))
        {
            return null;
        }

        return prop.ValueKind switch
        {
            JsonValueKind.String => prop.GetString(),
            JsonValueKind.Array => string.Join(", ", prop.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString())),
            JsonValueKind.Number => prop.ToString(),
            _ => null,
        };
    }
}
