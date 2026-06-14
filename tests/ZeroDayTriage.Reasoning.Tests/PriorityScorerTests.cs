using FluentAssertions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning;
using Xunit;

namespace ZeroDayTriage.Reasoning.Tests;

public sealed class PriorityScorerTests
{
    private readonly PriorityScorer _sut = new();

    private static AttackPath Path(
        Severity impact = Severity.High,
        Confidence confidence = Confidence.Confirmed,
        string objective = "Foothold",
        int hops = 1,
        string? techniqueOnFirstStep = null)
    {
        var steps = Enumerable.Range(0, hops).Select(i => new AttackStep
        {
            Action = $"step {i}",
            Tooling = "tool",
            Technique = i == 0 ? techniqueOnFirstStep : null,
        }).ToList();

        return new AttackPath
        {
            Name = "p",
            Objective = objective,
            Impact = impact,
            Confidence = confidence,
            Rationale = "r",
            Steps = steps,
        };
    }

    [Fact]
    public void Score_is_clamped_between_zero_and_one_hundred()
    {
        _sut.Score(Path(Severity.Critical, Confidence.Confirmed, "DCSync the domain"))
            .Should().BeInRange(0, 100);
    }

    [Fact]
    public void Higher_severity_scores_higher()
    {
        var low = _sut.Score(Path(Severity.Low));
        var crit = _sut.Score(Path(Severity.Critical));

        crit.Should().BeGreaterThan(low);
    }

    [Fact]
    public void Crown_jewel_objective_earns_a_bonus()
    {
        var ordinary = _sut.Score(Path(Severity.Critical, objective: "Lateral movement"));
        var crownJewel = _sut.Score(Path(Severity.Critical, objective: "Domain Admin via certificate abuse"));

        crownJewel.Should().BeGreaterThan(ordinary);
    }

    [Fact]
    public void Dcsync_technique_on_a_step_counts_as_crown_jewel()
    {
        var withDcSync = _sut.Score(Path(Severity.High, objective: "x", hops: 1, techniqueOnFirstStep: "T1003.006"));
        var without = _sut.Score(Path(Severity.High, objective: "x", hops: 1));

        withDcSync.Should().BeGreaterThan(without);
    }

    [Fact]
    public void Additional_hops_reduce_the_score()
    {
        var shortPath = _sut.Score(Path(Severity.High, hops: 1));
        var longPath = _sut.Score(Path(Severity.High, hops: 5));

        shortPath.Should().BeGreaterThan(longPath);
    }

    [Fact]
    public void Throws_on_null_path()
    {
        var act = () => _sut.Score(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}
