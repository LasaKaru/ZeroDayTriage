namespace ZeroDayTriage.Core.Model;

/// <summary>
/// A single actionable move in an attack path. Each step names the technique, the
/// concrete tool command an operator would run, and the findings that justify it.
/// </summary>
public sealed record AttackStep
{
    public required string Action { get; init; }

    /// <summary>The proven tool + invocation to execute this step (e.g. a Rubeus command line).</summary>
    public required string Tooling { get; init; }

    public KillChainPhase Phase { get; init; } = KillChainPhase.Exploit;

    public string? Technique { get; init; }

    /// <summary>Ids of the <see cref="Finding"/> records that evidence this step.</summary>
    public IReadOnlyList<string> EvidenceFindingIds { get; init; } = Array.Empty<string>();
}

/// <summary>
/// A reasoned chain from current foothold to an objective (typically Domain Admin or
/// DCSync). Produced by the reasoning engine, ranked by <see cref="Score"/>.
/// </summary>
public sealed record AttackPath
{
    public required string Name { get; init; }

    public required string Objective { get; init; }

    public AssetDomain Domain { get; init; } = AssetDomain.ActiveDirectory;

    public Severity Impact { get; init; } = Severity.High;

    public Confidence Confidence { get; init; } = Confidence.Probable;

    /// <summary>Composite priority score in [0, 100]; higher means chase it first.</summary>
    public double Score { get; init; }

    /// <summary>One-line operator rationale, e.g. why this beats the alternatives.</summary>
    public required string Rationale { get; init; }

    public IReadOnlyList<AttackStep> Steps { get; init; } = Array.Empty<AttackStep>();

    public int Hops => Steps.Count;
}
