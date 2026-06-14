using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Tools.Normalizers;

/// <summary>
/// Routes raw tool output to the first normalizer that recognizes it. Lets the CLI ingest
/// a directory of mixed tool dumps without the operator hand-labeling each file.
/// </summary>
public sealed class NormalizerRegistry
{
    private readonly IReadOnlyList<INormalizer> _normalizers;

    public NormalizerRegistry(IEnumerable<INormalizer> normalizers)
    {
        ArgumentNullException.ThrowIfNull(normalizers);
        _normalizers = normalizers.ToList();
    }

    /// <summary>Builds a registry wired with every built-in normalizer.</summary>
    public static NormalizerRegistry CreateDefault() => new(new INormalizer[]
    {
        new BloodHoundNormalizer(),
        new NetExecNormalizer(),
        new CertipyNormalizer(),
        new SlitherNormalizer(),
        new SuricataNormalizer(),
        new BeaconAnalysisNormalizer(),
        new MalwareConfigNormalizer(),
    });

    public IReadOnlyList<INormalizer> Normalizers => _normalizers;

    /// <summary>Returns the matching normalizer, or null when no normalizer claims the payload.</summary>
    public INormalizer? Resolve(string rawOutput) =>
        _normalizers.FirstOrDefault(n => n.CanParse(rawOutput));

    /// <summary>
    /// Parses with the best-matching normalizer. When <paramref name="source"/> is provided it
    /// is preferred over content sniffing. Returns an empty list when nothing matches.
    /// </summary>
    public IReadOnlyList<Finding> Normalize(string rawOutput, string? source = null)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return Array.Empty<Finding>();
        }

        if (source is not null)
        {
            var named = _normalizers.FirstOrDefault(
                n => string.Equals(n.Source, source, StringComparison.OrdinalIgnoreCase));
            if (named is not null && named.CanParse(rawOutput))
            {
                return named.Parse(rawOutput);
            }
        }

        return Resolve(rawOutput)?.Parse(rawOutput) ?? Array.Empty<Finding>();
    }
}
