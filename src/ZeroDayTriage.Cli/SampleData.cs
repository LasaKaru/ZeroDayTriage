using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Cli;

/// <summary>
/// A hand-built EVIL CORP banking scenario used by the <c>demo</c> command. It exercises a
/// fused chain (Kerberoastable service account that also holds GenericWrite), an AD CS ESC1,
/// a relay setup, and a smart-contract finding so the reasoning engine has real cross-domain
/// material to rank.
/// </summary>
public static class SampleData
{
    public static IReadOnlyList<Finding> EvilCorp() => new[]
    {
        new Finding
        {
            Title = "Kerberoastable account: SVC_SQL",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.High,
            Confidence = Confidence.Confirmed,
            Source = "sharphound",
            Principal = "EVILCORP\\SVC_SQL",
            Technique = "T1558.003",
            Tags = new[] { "kerberoastable", "ad", "credential-access" },
            Properties = new Dictionary<string, string> { ["spn"] = "MSSQLSvc/db01.evilcorp.local:1433" },
        }.WithComputedId(),

        new Finding
        {
            Title = "GenericWrite over OU=Servers",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.High,
            Confidence = Confidence.Confirmed,
            Source = "sharphound",
            Principal = "EVILCORP\\SVC_SQL",
            Technique = "T1222",
            Tags = new[] { "genericwrite", "ad", "acl-abuse" },
            Properties = new Dictionary<string, string> { ["target"] = "OU=Servers", ["right"] = "GenericWrite" },
        }.WithComputedId(),

        new Finding
        {
            Title = "AS-REP roastable account: AUDIT_SVC",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.High,
            Confidence = Confidence.Confirmed,
            Source = "sharphound",
            Principal = "EVILCORP\\AUDIT_SVC",
            Technique = "T1558.004",
            Tags = new[] { "asreproastable", "ad", "credential-access" },
        }.WithComputedId(),

        new Finding
        {
            Title = "AD CS ESC1 on template BankUserAuth",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.Critical,
            Confidence = Confidence.Confirmed,
            Source = "certipy",
            Principal = "BankUserAuth",
            Technique = "T1649",
            Tags = new[] { "adcs", "esc1", "privilege-escalation", "ad" },
            Properties = new Dictionary<string, string> { ["template"] = "BankUserAuth", ["esc"] = "ESC1" },
        }.WithComputedId(),

        new Finding
        {
            Title = "SMB signing not required on DC01",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.Medium,
            Confidence = Confidence.Confirmed,
            Source = "netexec",
            Principal = "DC01",
            Technique = "T1557.001",
            Tags = new[] { "smb-signing-off", "relay-target", "ad" },
        }.WithComputedId(),

        new Finding
        {
            Title = "Admin access as EVILCORP\\backupadmin on FS01",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.Critical,
            Confidence = Confidence.Confirmed,
            Source = "netexec",
            Principal = "EVILCORP\\backupadmin",
            Technique = "T1550.002",
            Tags = new[] { "valid-credential", "ntlm-hash", "pass-the-hash", "local-admin", "ad" },
            Properties = new Dictionary<string, string> { ["host"] = "FS01", ["protocol"] = "SMB", ["secretType"] = "ntlm" },
        }.WithComputedId(),

        new Finding
        {
            Title = "Solidity: reentrancy-eth (High)",
            Domain = AssetDomain.SmartContract,
            Severity = Severity.Critical,
            Confidence = Confidence.Probable,
            Source = "slither",
            Principal = "VaultBank.withdraw()",
            Tags = new[] { "smart-contract", "reentrancy-eth", "static-analysis" },
            Properties = new Dictionary<string, string> { ["check"] = "reentrancy-eth", ["impact"] = "High" },
        }.WithComputedId(),

        // Deliberate low-value noise to prove the engine filters it.
        new Finding
        {
            Title = "Password policy: minimum length 7",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.Low,
            Confidence = Confidence.Suspected,
            Source = "netexec",
            Principal = "EVILCORP",
            Tags = new[] { "policy", "informational" },
        }.WithComputedId(),
    };
}
