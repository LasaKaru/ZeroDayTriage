using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning.Rules;

namespace ZeroDayTriage.Reasoning;

/// <summary>
/// The AI-triage brain described in the plan: it ingests normalized findings, runs every
/// attack-path rule, scores and ranks the resulting paths, and flags the findings that did
/// not contribute to any real path as noise. The output is a single prioritized
/// <see cref="TriageReport"/> the operator acts on.
/// </summary>
public sealed class ReasoningEngine
{
    private readonly IReadOnlyList<IAttackPathRule> _rules;
    private readonly PriorityScorer _scorer;

    public ReasoningEngine(IEnumerable<IAttackPathRule> rules, PriorityScorer? scorer = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        _rules = rules.ToList();
        _scorer = scorer ?? new PriorityScorer();
    }

    /// <summary>Engine wired with the full built-in rule set.</summary>
    public static ReasoningEngine CreateDefault() => new(new IAttackPathRule[]
    {
        // Phase 1 — Initial Access
        new InitialAccessRule(),
        new AsRepRoastRule(),
        // Phase 2 — Command & Control
        new C2DetectionRule(),
        // Phase 3 — Privilege Escalation
        new KerberoastingRule(),
        new AdcsEscalationRule(),
        new AclEscalationRule(),
        new PassTheHashRule(),
        new CoercionRelayRule(),
        new DcSyncRule(),
        new UnconstrainedDelegationRule(),
        // Phase 4 — Malware Triage
        new MalwareTriageRule(),
        // Phase 5 — Data Exfiltration
        new ExfiltrationRule(),
        // Bonus battleground — smart contracts
        new SmartContractRule(),
    });

    public IReadOnlyList<IAttackPathRule> Rules => _rules;

    public TriageReport Triage(IEnumerable<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var corpus = new FindingCorpus(findings);

        var paths = new List<AttackPath>();
        foreach (var rule in _rules)
        {
            // A faulty rule must never sink the whole triage pass.
            IEnumerable<AttackPath> produced;
            try
            {
                produced = rule.Evaluate(corpus).ToList();
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var path in produced)
            {
                paths.Add(path with { Score = _scorer.Score(path) });
            }
        }

        var ranked = paths
            .OrderByDescending(p => p.Score)
            .ThenByDescending(p => (int)p.Impact)
            .ThenBy(p => p.Hops)
            .ToList();

        var referenced = ranked
            .SelectMany(p => p.Steps)
            .SelectMany(s => s.EvidenceFindingIds)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var noise = corpus.All
            .Where(f => IsNoise(f, referenced))
            .Select(f => $"{f.Id}: {f.Title}")
            .ToList();

        var byDomain = corpus.All
            .GroupBy(f => f.Domain)
            .ToDictionary(g => g.Key, g => g.Count());

        var byPhase = ranked
            .GroupBy(p => p.Phase)
            .ToDictionary(g => g.Key, g => g.Count());

        var phasesCovered = byPhase.Keys
            .OrderBy(p => (int)p)
            .ToList();

        return new TriageReport
        {
            FindingsConsidered = corpus.Count,
            Paths = ranked,
            SuppressedAsNoise = noise,
            FindingsByDomain = byDomain,
            PathsByPhase = byPhase,
            PhasesCovered = phasesCovered,
        };
    }

    /// <summary>
    /// A finding is noise when it never fed an attack path AND is not independently
    /// significant (low severity or merely suspected). This keeps confirmed high-severity
    /// findings visible even if no rule chained them yet.
    /// </summary>
    private static bool IsNoise(Finding finding, IReadOnlySet<string> referenced)
    {
        if (referenced.Contains(finding.Id))
        {
            return false;
        }

        if (finding.Severity >= Severity.High && finding.Confidence == Confidence.Confirmed)
        {
            return false;
        }

        return finding.Confidence == Confidence.Suspected || finding.Severity <= Severity.Low;
    }
}
