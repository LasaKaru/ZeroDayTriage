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
                ExtractGraphEdges(node, name, findings);
                FlagHighValue(node, name, findings);
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

    /// <summary>
    /// Emits the BloodHound graph edges the path-finder consumes: group membership, local-admin,
    /// RDP/PSRemote/DCOM access, and active sessions. Every edge finding carries the source as
    /// <see cref="Finding.Principal"/> and the target in the "target" property, with an "edge" tag.
    /// </summary>
    private void ExtractGraphEdges(JsonElement node, string name, List<Finding> findings)
    {
        // Group node: each member -> this group (MemberOf).
        foreach (var member in ReadIdentifiers(node, "Members"))
        {
            findings.Add(EdgeFinding("memberof", member, name, Severity.Low,
                $"{member} is a member of {name}", "T1078"));
        }

        // Computer node edges. Direction encodes "controlling source lets you control target".
        foreach (var admin in ReadIdentifiers(node, "LocalAdmins"))
        {
            findings.Add(EdgeFinding("adminto", admin, name, Severity.High,
                $"{admin} is local admin on {name}", "T1078.002"));
        }

        foreach (var rdp in ReadIdentifiers(node, "RemoteDesktopUsers"))
        {
            findings.Add(EdgeFinding("canrdp", rdp, name, Severity.Medium,
                $"{rdp} can RDP to {name}", "T1021.001"));
        }

        foreach (var ps in ReadIdentifiers(node, "PSRemoteUsers"))
        {
            findings.Add(EdgeFinding("canpsremote", ps, name, Severity.Medium,
                $"{ps} can PSRemote to {name}", "T1021.006"));
        }

        foreach (var dcom in ReadIdentifiers(node, "DcomUsers"))
        {
            findings.Add(EdgeFinding("executedcom", dcom, name, Severity.Medium,
                $"{dcom} can ExecuteDCOM on {name}", "T1021.003"));
        }

        // Sessions: controlling the computer lets you steal the session user's credentials.
        foreach (var user in ReadSessionUsers(node))
        {
            findings.Add(EdgeFinding("hassession", name, user, Severity.Medium,
                $"{user} has a session on {name}", "T1003"));
        }
    }

    private Finding EdgeFinding(string edge, string source, string target, Severity severity, string evidence, string technique) =>
        new Finding
        {
            Title = $"{edge}: {source} -> {target}",
            Domain = AssetDomain.ActiveDirectory,
            Severity = severity,
            Confidence = Confidence.Confirmed,
            Source = Source,
            Principal = source,
            Technique = technique,
            Tags = new[] { edge, "graph-edge", "ad" },
            Properties = new Dictionary<string, string> { ["target"] = target, ["edge"] = edge },
            Evidence = evidence,
        };

    private void FlagHighValue(JsonElement node, string name, List<Finding> findings)
    {
        if (node.TryGetProperty("Properties", out var props) &&
            TryGetBool(props, "highvalue", out var hv) && hv)
        {
            findings.Add(new Finding
            {
                Title = $"High-value target: {name}",
                Domain = AssetDomain.ActiveDirectory,
                Severity = Severity.Info,
                Confidence = Confidence.Confirmed,
                Source = Source,
                Principal = name,
                Tags = new[] { "highvalue", "ad" },
                Properties = new Dictionary<string, string> { ["target"] = name },
            });
        }
    }

    /// <summary>
    /// Reads a BloodHound edge array (Members, LocalAdmins, ...). Entries may be plain strings,
    /// or objects carrying ObjectIdentifier / name. Identity resolution prefers a readable name.
    /// </summary>
    private static IEnumerable<string> ReadIdentifiers(JsonElement node, string property)
    {
        if (!node.TryGetProperty(property, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var entry in array.EnumerateArray())
        {
            var id = entry.ValueKind switch
            {
                JsonValueKind.String => entry.GetString(),
                JsonValueKind.Object => GetString(entry, "name")
                    ?? GetString(entry, "ObjectIdentifier")
                    ?? GetString(entry, "MemberId"),
                _ => null,
            };

            if (!string.IsNullOrWhiteSpace(id))
            {
                yield return id!;
            }
        }
    }

    private static IEnumerable<string> ReadSessionUsers(JsonElement node)
    {
        // Sessions can appear as a bare array or wrapped as { "Results": [...] }.
        if (!node.TryGetProperty("Sessions", out var sessions))
        {
            yield break;
        }

        var array = sessions;
        if (sessions.ValueKind == JsonValueKind.Object &&
            sessions.TryGetProperty("Results", out var results))
        {
            array = results;
        }

        if (array.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var entry in array.EnumerateArray())
        {
            var user = entry.ValueKind switch
            {
                JsonValueKind.String => entry.GetString(),
                JsonValueKind.Object => GetString(entry, "UserName")
                    ?? GetString(entry, "UserSID")
                    ?? GetString(entry, "user"),
                _ => null,
            };

            if (!string.IsNullOrWhiteSpace(user))
            {
                yield return user!;
            }
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
