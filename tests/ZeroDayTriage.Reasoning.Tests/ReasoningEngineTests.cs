using FluentAssertions;
using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning;
using ZeroDayTriage.Reasoning.Rules;
using Xunit;
using static ZeroDayTriage.Reasoning.Tests.Builders;

namespace ZeroDayTriage.Reasoning.Tests;

public sealed class ReasoningEngineTests
{
    [Fact]
    public void Triage_ranks_paths_by_descending_score()
    {
        var engine = ReasoningEngine.CreateDefault();

        var report = engine.Triage(new[]
        {
            Finding("ESC1", "Tmpl", technique: "T1649",
                properties: new Dictionary<string, string> { ["template"] = "Tmpl", ["esc"] = "ESC1" },
                tags: new[] { "adcs", "esc1" }),
            Kerberoastable("SVC_SQL"),
        });

        report.Paths.Should().BeInDescendingOrder(p => p.Score);
        report.TopPath!.Name.Should().Contain("ESC1");
    }

    [Fact]
    public void Triage_filters_low_value_suspected_findings_as_noise()
    {
        var engine = ReasoningEngine.CreateDefault();

        var report = engine.Triage(new[]
        {
            Kerberoastable("SVC_SQL"),
            Finding("weak password policy", "EVILCORP", severity: Severity.Low,
                confidence: Confidence.Suspected, tags: "policy"),
        });

        report.SuppressedAsNoise.Should().ContainSingle(n => n.Contains("weak password policy"));
    }

    [Fact]
    public void Triage_keeps_confirmed_high_severity_findings_out_of_noise()
    {
        var engine = ReasoningEngine.CreateDefault();
        var orphan = Finding("confirmed but unchained", "X", severity: Severity.High, confidence: Confidence.Confirmed, tags: "weird");

        var report = engine.Triage(new[] { orphan });

        report.SuppressedAsNoise.Should().NotContain(n => n.Contains("confirmed but unchained"));
    }

    [Fact]
    public void Triage_reports_findings_by_domain()
    {
        var engine = ReasoningEngine.CreateDefault();

        var report = engine.Triage(new[]
        {
            Kerberoastable("SVC_SQL"),
            Finding("contract", "V", domain: AssetDomain.SmartContract, tags: "smart-contract"),
        });

        report.FindingsByDomain[AssetDomain.ActiveDirectory].Should().Be(1);
        report.FindingsByDomain[AssetDomain.SmartContract].Should().Be(1);
        report.FindingsConsidered.Should().Be(2);
    }

    [Fact]
    public void Triage_with_no_findings_yields_no_paths()
    {
        var report = ReasoningEngine.CreateDefault().Triage(Array.Empty<Finding>());

        report.Paths.Should().BeEmpty();
        report.TopPath.Should().BeNull();
    }

    [Fact]
    public void A_throwing_rule_does_not_sink_the_pass()
    {
        var engine = new ReasoningEngine(new IAttackPathRule[]
        {
            new ThrowingRule(),
            new KerberoastingRule(),
        });

        var report = engine.Triage(new[] { Kerberoastable("SVC_SQL") });

        report.Paths.Should().NotBeEmpty();
    }

    [Fact]
    public void CreateDefault_wires_the_full_rule_set()
    {
        ReasoningEngine.CreateDefault().Rules.Select(r => r.Id)
            .Should().Contain(new[]
            {
                "EC-INITIAL-ACCESS", "EC-C2", "AD-KERBEROAST", "AD-ADCS", "AD-ACL", "AD-PTH",
                "AD-DCSYNC", "AD-UNCONSTRAINED", "EC-MALWARE", "EC-EXFIL", "CHAIN-SOLIDITY",
            });
    }

    [Fact]
    public void Triage_reports_all_five_kill_chain_phases_when_present()
    {
        var engine = ReasoningEngine.CreateDefault();

        var report = engine.Triage(new[]
        {
            Finding("SocGholish", "10.0.0.1", AssetDomain.Network,
                properties: new Dictionary<string, string> { ["src_ip"] = "10.0.0.1" }, tags: "initial-access"),
            Finding("beacon", "10.0.0.1", AssetDomain.Network,
                properties: new Dictionary<string, string> { ["source"] = "10.0.0.1", ["destination"] = "1.2.3.4" }, tags: "c2-beacon"),
            Finding("dcsync", "svc", technique: "T1003.006", severity: Severity.Critical, tags: "dcsync"),
            Finding("Dridex", "hash", AssetDomain.Endpoint,
                properties: new Dictionary<string, string> { ["family"] = "Dridex" }, tags: new[] { "malware", "triage" }),
            Finding("exfil", "10.0.0.9", AssetDomain.Network,
                properties: new Dictionary<string, string> { ["src_ip"] = "10.0.0.9" }, tags: "exfiltration"),
        });

        report.PhasesCovered.Should().BeEquivalentTo(new[]
        {
            MissionPhase.InitialAccess, MissionPhase.CommandAndControl, MissionPhase.PrivilegeEscalation,
            MissionPhase.MalwareTriage, MissionPhase.DataExfiltration,
        });
    }

    private sealed class ThrowingRule : IAttackPathRule
    {
        public string Id => "FAULTY";
        public string Description => "always throws";
        public AssetDomain Domain => AssetDomain.Unknown;
        public IEnumerable<AttackPath> Evaluate(FindingCorpus findings) =>
            throw new InvalidOperationException("boom");
    }
}
