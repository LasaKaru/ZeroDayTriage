namespace ZeroDayTriage.Core.Model;

/// <summary>
/// The final product of a triage pass: the prioritized attack paths, the single
/// recommended next action, and the counts the operator needs at a glance.
/// </summary>
public sealed record TriageReport
{
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

    public int FindingsConsidered { get; init; }

    /// <summary>Attack paths ordered by descending <see cref="AttackPath.Score"/>.</summary>
    public IReadOnlyList<AttackPath> Paths { get; init; } = Array.Empty<AttackPath>();

    /// <summary>
    /// Findings the engine suppressed as noise (low confidence, no exploitable edge).
    /// Surfaced so the operator can audit what was filtered rather than silently dropped.
    /// </summary>
    public IReadOnlyList<string> SuppressedAsNoise { get; init; } = Array.Empty<string>();

    /// <summary>The highest-scoring path, or null when nothing actionable was found.</summary>
    public AttackPath? TopPath => Paths.Count > 0 ? Paths[0] : null;

    public IReadOnlyDictionary<AssetDomain, int> FindingsByDomain { get; init; }
        = new Dictionary<AssetDomain, int>();
}
