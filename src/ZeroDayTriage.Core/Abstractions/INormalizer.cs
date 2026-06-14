using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Core.Abstractions;

/// <summary>
/// Parses a single proven tool's native output into normalized <see cref="Finding"/>
/// records. One normalizer per tool family (BloodHound, NetExec, Certipy, Slither ...).
/// </summary>
public interface INormalizer
{
    /// <summary>The source identifier stamped onto findings (e.g. "sharphound").</summary>
    string Source { get; }

    /// <summary>Cheap test for whether this normalizer recognizes the payload.</summary>
    bool CanParse(string rawOutput);

    /// <summary>
    /// Transforms raw tool output into findings. Implementations must be resilient to
    /// partial or malformed input and never throw on garbage — they return what they
    /// could salvage.
    /// </summary>
    IReadOnlyList<Finding> Parse(string rawOutput);
}
