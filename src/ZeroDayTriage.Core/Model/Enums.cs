namespace ZeroDayTriage.Core.Model;

/// <summary>
/// The operational domain a finding or asset belongs to. Mirrors the six
/// battlegrounds of Project ZeroDay 2026.
/// </summary>
public enum AssetDomain
{
    Unknown = 0,
    ActiveDirectory,
    Cloud,
    Linux,
    Windows,
    Kubernetes,
    SmartContract,

    /// <summary>Wire-level evidence: IDS alerts, C2 beaconing, exfiltration flows.</summary>
    Network,

    /// <summary>Host/endpoint artifacts: initial-access droppers, malware samples, configs.</summary>
    Endpoint,
}

/// <summary>
/// The five progressive phases of the EVIL CORP banking intrusion the event is modeled on.
/// Mapping findings and paths to a phase lets the operator see kill-chain coverage at a glance
/// and tells the investigator which part of the story a clue belongs to.
/// </summary>
public enum MissionPhase
{
    /// <summary>Weaponized "update" droppers (SocGholish), drive-by, phishing — the foothold.</summary>
    InitialAccess = 0,

    /// <summary>Encrypted C2 beaconing, Cobalt Strike / Dridex traffic, evasion.</summary>
    CommandAndControl = 1,

    /// <summary>Workstation -> Domain Controller pivot inside Active Directory.</summary>
    PrivilegeEscalation = 2,

    /// <summary>Reverse-engineering trojans/ransomware: config, crypto keys, IOCs.</summary>
    MalwareTriage = 3,

    /// <summary>Locating and draining the targeted databases / financial records.</summary>
    DataExfiltration = 4,
}

/// <summary>
/// Impact rating of a finding, ordered so numeric comparison is meaningful.
/// </summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>
/// How sure the operator can be that a finding is real and actionable.
/// This is the lever the AI-triage layer uses to filter noise from signal.
/// </summary>
public enum Confidence
{
    /// <summary>Heuristic match only; likely noise until corroborated.</summary>
    Suspected = 0,

    /// <summary>Strong indicators, but not yet validated end to end.</summary>
    Probable = 1,

    /// <summary>Validated by tooling output or cross-referenced evidence.</summary>
    Confirmed = 2,
}

/// <summary>
/// The four-loop kill-chain phase a recommended action advances.
/// Enumerate -> Identify -> Exploit -> Loot &amp; Pivot.
/// </summary>
public enum KillChainPhase
{
    Enumerate = 0,
    Identify = 1,
    Exploit = 2,
    LootAndPivot = 3,
}
