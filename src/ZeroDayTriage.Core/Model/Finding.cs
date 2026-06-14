using System.Security.Cryptography;
using System.Text;

namespace ZeroDayTriage.Core.Model;

/// <summary>
/// A normalized observation produced by a tool runner. Every runner — SharpHound,
/// NetExec, Certipy, Slither, etc. — collapses its native output into a stream of
/// <see cref="Finding"/> records so the reasoning engine sees one shape regardless
/// of which tool spoke.
/// </summary>
public sealed record Finding
{
    /// <summary>Stable identity derived from the content fingerprint. Used for de-duplication.</summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>Short, human-readable headline (e.g. "Kerberoastable SPN on SVC_SQL").</summary>
    public required string Title { get; init; }

    /// <summary>Which battleground this belongs to.</summary>
    public AssetDomain Domain { get; init; } = AssetDomain.Unknown;

    public Severity Severity { get; init; } = Severity.Info;

    public Confidence Confidence { get; init; } = Confidence.Suspected;

    /// <summary>The tool that produced the observation (e.g. "sharphound", "netexec").</summary>
    public required string Source { get; init; }

    /// <summary>
    /// The primary subject — a user, computer, service principal, IAM role, pod, or
    /// contract address. Used to stitch findings into attack paths.
    /// </summary>
    public string? Principal { get; init; }

    /// <summary>
    /// MITRE ATT&amp;CK technique id when known (e.g. "T1558.003" Kerberoasting).
    /// </summary>
    public string? Technique { get; init; }

    /// <summary>Free-form, tool-specific structured attributes.</summary>
    public IReadOnlyDictionary<string, string> Properties { get; init; }
        = new Dictionary<string, string>();

    /// <summary>Searchable labels used by reasoning rules (e.g. "kerberoastable", "dcsync").</summary>
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();

    /// <summary>Raw tool excerpt kept for the operator's audit trail.</summary>
    public string? Evidence { get; init; }

    public DateTimeOffset DiscoveredAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Computes a deterministic fingerprint over the load-bearing fields so the same
    /// observation seen twice collapses to one row. Returns a new record with <see cref="Id"/> set.
    /// </summary>
    public Finding WithComputedId()
    {
        var seed = string.Join(
            "|",
            Source.ToLowerInvariant(),
            Domain.ToString(),
            Title.Trim().ToLowerInvariant(),
            Principal?.Trim().ToLowerInvariant() ?? string.Empty,
            Technique ?? string.Empty);

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        var id = Convert.ToHexString(bytes, 0, 8).ToLowerInvariant();
        return this with { Id = id };
    }

    public bool HasTag(string tag) =>
        Tags.Any(t => string.Equals(t, tag, StringComparison.OrdinalIgnoreCase));

    public string? Property(string key) =>
        Properties.TryGetValue(key, out var value) ? value : null;
}
