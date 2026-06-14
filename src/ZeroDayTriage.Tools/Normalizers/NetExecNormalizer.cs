using System.Text.RegularExpressions;
using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Tools.Normalizers;

/// <summary>
/// Parses NetExec (nxc) / CrackMapExec console output. Recognizes valid credential lines,
/// administrative access ("Pwn3d!"), and SMB signing posture, which together feed
/// pass-the-hash, lateral-movement, and relay attack paths.
/// </summary>
public sealed partial class NetExecNormalizer : INormalizer
{
    public string Source => "netexec";

    // Example:
    // SMB  10.10.0.5  445  DC01  [+] evilcorp.local\svc_sql:Summer2024! (Pwn3d!)
    [GeneratedRegex(
        @"^(?<proto>SMB|LDAP|WINRM|MSSQL|RDP|SSH)\s+(?<host>\S+)\s+(?<port>\d+)\s+(?<name>\S+)\s+\[(?<status>[+\-*])\]\s+(?<body>.+)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex LineRegex();

    // evilcorp.local\svc_sql:Summer2024!  (optionally trailed by markers)
    [GeneratedRegex(
        @"^(?<domain>[^\\\s]+)\\(?<user>[^:]+):(?<secret>\S+)",
        RegexOptions.Compiled)]
    private static partial Regex CredentialRegex();

    public bool CanParse(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return false;
        }

        foreach (var line in EnumerateLines(rawOutput))
        {
            if (LineRegex().IsMatch(line.Trim()))
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

        foreach (var rawLine in EnumerateLines(rawOutput))
        {
            var line = rawLine.Trim();
            var match = LineRegex().Match(line);
            if (!match.Success)
            {
                continue;
            }

            var proto = match.Groups["proto"].Value.ToUpperInvariant();
            var host = match.Groups["host"].Value;
            var name = match.Groups["name"].Value;
            var status = match.Groups["status"].Value;
            var body = match.Groups["body"].Value.Trim();

            // Signing / posture signal lines. The computer name is the relay target identity;
            // the IP is kept as a property for the operator.
            if (body.Contains("signing:False", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Title = $"SMB signing not required on {name}",
                    Domain = AssetDomain.ActiveDirectory,
                    Severity = Severity.Medium,
                    Confidence = Confidence.Confirmed,
                    Source = Source,
                    Principal = name,
                    Technique = "T1557.001",
                    Tags = new[] { "smb-signing-off", "relay-target", "ad" },
                    Properties = new Dictionary<string, string> { ["host"] = host },
                    Evidence = line,
                });
            }

            if (status != "+")
            {
                continue;
            }

            var cred = CredentialRegex().Match(body);
            if (!cred.Success)
            {
                continue;
            }

            var domain = cred.Groups["domain"].Value;
            var user = cred.Groups["user"].Value;
            var secret = cred.Groups["secret"].Value;
            var isHash = LooksLikeNtlm(secret);
            var isAdmin = body.Contains("Pwn3d!", StringComparison.OrdinalIgnoreCase);

            var tags = new List<string> { "valid-credential", "ad" };
            if (isHash)
            {
                tags.Add("ntlm-hash");
                tags.Add("pass-the-hash");
            }

            if (isAdmin)
            {
                tags.Add("local-admin");
            }

            findings.Add(new Finding
            {
                Title = isAdmin
                    ? $"Admin access as {domain}\\{user} on {host}"
                    : $"Valid credentials for {domain}\\{user}",
                Domain = AssetDomain.ActiveDirectory,
                Severity = isAdmin ? Severity.Critical : Severity.High,
                Confidence = Confidence.Confirmed,
                Source = Source,
                Principal = $"{domain}\\{user}",
                Technique = isHash ? "T1550.002" : "T1078.002",
                Tags = tags,
                Properties = new Dictionary<string, string>
                {
                    ["host"] = host,
                    ["protocol"] = proto,
                    ["secretType"] = isHash ? "ntlm" : "password",
                },
                Evidence = line,
            });
        }

        return findings.Select(f => f.WithComputedId()).ToList();
    }

    private static bool LooksLikeNtlm(string secret)
    {
        // aad3b...:NThash  or a bare 32-hex NT hash.
        if (secret.Contains(':'))
        {
            var parts = secret.Split(':');
            return parts.Length == 2 && parts.All(IsHex32);
        }

        return IsHex32(secret);
    }

    private static bool IsHex32(string value) =>
        value.Length == 32 && value.All(Uri.IsHexDigit);

    private static IEnumerable<string> EnumerateLines(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
}
