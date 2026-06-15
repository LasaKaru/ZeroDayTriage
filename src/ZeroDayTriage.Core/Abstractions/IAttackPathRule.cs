using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Core.Abstractions;

/// <summary>
/// A single piece of attack-path knowledge. Given the full corpus of findings, a rule
/// emits zero or more candidate <see cref="AttackPath"/> records. Rules are deliberately
/// small and composable — Kerberoasting, AS-REP roasting, ADCS ESC1, unconstrained
/// delegation, DCSync, etc. The reasoning engine runs them all and ranks the union.
/// </summary>
public interface IAttackPathRule
{
    /// <summary>Stable rule identifier, used in logs and tests.</summary>
    string Id { get; }

    string Description { get; }

    AssetDomain Domain { get; }

    /// <summary>
    /// Evaluates the rule against the corpus. The <paramref name="findings"/> are indexed
    /// for convenience but a rule may scan the whole set to correlate across principals.
    /// </summary>
    IEnumerable<AttackPath> Evaluate(FindingCorpus findings);
}
