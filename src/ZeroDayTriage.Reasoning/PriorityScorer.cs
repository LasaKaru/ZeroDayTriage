using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning;

/// <summary>
/// Turns the qualitative attributes of an attack path into a single comparable score in
/// [0, 100]. The model rewards impact and confidence, gives a bonus for chains that reach a
/// crown-jewel objective, and penalizes long, fragile paths — encoding the operator instinct
/// to chase the shortest reliable route to Domain Admin.
/// </summary>
public sealed class PriorityScorer
{
    // Weights are deliberately explicit and summed so the model is auditable and testable.
    private const double SeverityWeight = 14.0;   // x severity rank (0..4) => up to 56
    private const double ConfidenceWeight = 9.0;  // x confidence rank (0..2) => up to 18
    private const double CrownJewelBonus = 20.0;  // path reaches DCSync / Domain Admin
    private const double HopPenalty = 3.5;         // per hop beyond the first

    private static readonly string[] CrownJewelMarkers =
    {
        "domain admin", "dcsync", "krbtgt", "golden ticket", "enterprise admin",
    };

    public double Score(AttackPath path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var severityRank = (int)path.Impact;     // Info(0) .. Critical(4)
        var confidenceRank = (int)path.Confidence; // Suspected(0) .. Confirmed(2)

        var score = severityRank * SeverityWeight;
        score += confidenceRank * ConfidenceWeight;

        if (ReachesCrownJewel(path))
        {
            score += CrownJewelBonus;
        }

        var extraHops = Math.Max(0, path.Hops - 1);
        score -= extraHops * HopPenalty;

        return Math.Clamp(score, 0.0, 100.0);
    }

    private static bool ReachesCrownJewel(AttackPath path)
    {
        if (ContainsMarker(path.Objective) || ContainsMarker(path.Name))
        {
            return true;
        }

        return path.Steps.Any(s =>
            ContainsMarker(s.Action) ||
            ContainsMarker(s.Tooling) ||
            string.Equals(s.Technique, "T1003.006", StringComparison.OrdinalIgnoreCase));
    }

    private static bool ContainsMarker(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        foreach (var marker in CrownJewelMarkers)
        {
            if (text.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
