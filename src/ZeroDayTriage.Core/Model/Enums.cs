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
