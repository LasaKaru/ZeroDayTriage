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

        // --- BloodHound graph chain: jdoe -> WS01 -> svc_adm -> Domain Admins ---
        new Finding
        {
            Title = "Valid credentials for EVILCORP\\jdoe",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.High,
            Confidence = Confidence.Confirmed,
            Source = "netexec",
            Principal = "EVILCORP\\jdoe",
            Technique = "T1078.002",
            Tags = new[] { "valid-credential", "ad" },
            Properties = new Dictionary<string, string> { ["host"] = "WS01" },
        }.WithComputedId(),
        new Finding
        {
            Title = "adminto: EVILCORP\\jdoe -> WS01",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.High,
            Confidence = Confidence.Confirmed,
            Source = "sharphound",
            Principal = "EVILCORP\\jdoe",
            Technique = "T1078.002",
            Tags = new[] { "adminto", "graph-edge", "ad" },
            Properties = new Dictionary<string, string> { ["target"] = "WS01", ["edge"] = "adminto" },
        }.WithComputedId(),
        new Finding
        {
            Title = "hassession: WS01 -> EVILCORP\\svc_adm",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.Medium,
            Confidence = Confidence.Confirmed,
            Source = "sharphound",
            Principal = "WS01",
            Technique = "T1003",
            Tags = new[] { "hassession", "graph-edge", "ad" },
            Properties = new Dictionary<string, string> { ["target"] = "EVILCORP\\svc_adm", ["edge"] = "hassession" },
        }.WithComputedId(),
        new Finding
        {
            Title = "memberof: EVILCORP\\svc_adm -> Domain Admins",
            Domain = AssetDomain.ActiveDirectory,
            Severity = Severity.Low,
            Confidence = Confidence.Confirmed,
            Source = "sharphound",
            Principal = "EVILCORP\\svc_adm",
            Technique = "T1078",
            Tags = new[] { "memberof", "graph-edge", "ad" },
            Properties = new Dictionary<string, string> { ["target"] = "Domain Admins", ["edge"] = "memberof" },
        }.WithComputedId(),

        // --- Phase 1: Initial Access (SocGholish fake-update dropper) ---
        new Finding
        {
            Title = "ET MALWARE SocGholish Fake Browser Update",
            Domain = AssetDomain.Network,
            Phase = MissionPhase.InitialAccess,
            Severity = Severity.Critical,
            Confidence = Confidence.Probable,
            Source = "suricata",
            Principal = "10.20.1.44",
            Technique = "T1189",
            Tags = new[] { "initial-access", "ids", "network" },
            Properties = new Dictionary<string, string> { ["src_ip"] = "10.20.1.44", ["dest_ip"] = "185.99.4.10" },
        }.WithComputedId(),

        // --- Phase 2: Command & Control (RITA beacon) ---
        new Finding
        {
            Title = "C2 beacon 10.20.1.44 -> 185.99.4.10 (score 0.97)",
            Domain = AssetDomain.Network,
            Phase = MissionPhase.CommandAndControl,
            Severity = Severity.Critical,
            Confidence = Confidence.Confirmed,
            Source = "rita",
            Principal = "10.20.1.44",
            Technique = "T1071.001",
            Tags = new[] { "c2-beacon", "network", "high-confidence" },
            Properties = new Dictionary<string, string>
            {
                ["score"] = "0.970", ["source"] = "10.20.1.44", ["destination"] = "185.99.4.10",
            },
        }.WithComputedId(),

        // --- Phase 4: Malware Triage (Dridex config: keys + C2) ---
        new Finding
        {
            Title = "Banking trojan triaged: Dridex",
            Domain = AssetDomain.Endpoint,
            Phase = MissionPhase.MalwareTriage,
            Severity = Severity.Critical,
            Confidence = Confidence.Confirmed,
            Source = "malware-config",
            Principal = "e3b0c44298fc1c149afbf4c8996fb924",
            Technique = "T1005",
            Tags = new[] { "malware", "banking-trojan", "triage" },
            Properties = new Dictionary<string, string> { ["family"] = "Dridex" },
        }.WithComputedId(),
        new Finding
        {
            Title = "Extracted rc4 key from Dridex",
            Domain = AssetDomain.Endpoint,
            Phase = MissionPhase.MalwareTriage,
            Severity = Severity.High,
            Confidence = Confidence.Confirmed,
            Source = "malware-config",
            Principal = "Dridex",
            Technique = "T1005",
            Tags = new[] { "crypto-key", "ioc", "malware" },
            Properties = new Dictionary<string, string> { ["keyType"] = "rc4", ["family"] = "Dridex" },
        }.WithComputedId(),
        new Finding
        {
            Title = "C2 infrastructure for Dridex: 185.99.4.10:443",
            Domain = AssetDomain.Network,
            Phase = MissionPhase.CommandAndControl,
            Severity = Severity.High,
            Confidence = Confidence.Confirmed,
            Source = "malware-config",
            Principal = "185.99.4.10:443",
            Technique = "T1071",
            Tags = new[] { "c2-infra", "ioc", "network", "malware" },
            Properties = new Dictionary<string, string> { ["family"] = "Dridex", ["endpoint"] = "185.99.4.10:443" },
        }.WithComputedId(),

        // --- Phase 5: Data Exfiltration ---
        new Finding
        {
            Title = "ET POLICY Large Outbound Transfer to External Host",
            Domain = AssetDomain.Network,
            Phase = MissionPhase.DataExfiltration,
            Severity = Severity.Critical,
            Confidence = Confidence.Probable,
            Source = "suricata",
            Principal = "10.20.5.9",
            Technique = "T1041",
            Tags = new[] { "exfiltration", "ids", "network" },
            Properties = new Dictionary<string, string> { ["src_ip"] = "10.20.5.9", ["dest_ip"] = "185.99.4.10" },
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
