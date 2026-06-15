using FluentAssertions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning.Rules;
using Xunit;
using static ZeroDayTriage.Reasoning.Tests.Builders;

namespace ZeroDayTriage.Reasoning.Tests;

public sealed class InitialAccessRuleTests
{
    private readonly InitialAccessRule _sut = new();

    [Fact]
    public void Builds_a_foothold_path_from_a_dropper_alert()
    {
        var corpus = Corpus(Finding("SocGholish Fake Update", "10.20.1.44", AssetDomain.Network,
            severity: Severity.Critical, confidence: Confidence.Probable, source: "suricata",
            properties: new Dictionary<string, string> { ["src_ip"] = "10.20.1.44" },
            tags: new[] { "initial-access" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Phase.Should().Be(MissionPhase.InitialAccess);
        path.Steps.Should().HaveCount(2);
        path.Rationale.Should().Contain("patient zero");
    }
}

public sealed class C2DetectionRuleTests
{
    private readonly C2DetectionRule _sut = new();

    [Fact]
    public void Traces_a_beacon_into_a_containment_path()
    {
        var corpus = Corpus(Finding("beacon", "10.20.1.44", AssetDomain.Network,
            severity: Severity.Critical, confidence: Confidence.Confirmed, source: "rita",
            properties: new Dictionary<string, string> { ["source"] = "10.20.1.44", ["destination"] = "185.99.4.10" },
            tags: new[] { "c2-beacon" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Phase.Should().Be(MissionPhase.CommandAndControl);
        path.Name.Should().Contain("185.99.4.10");
    }

    [Fact]
    public void Deduplicates_when_a_finding_carries_both_tags()
    {
        var corpus = Corpus(Finding("beacon+infra", "h", AssetDomain.Network,
            tags: new[] { "c2-beacon", "c2-infra" }));

        _sut.Evaluate(corpus).Should().ContainSingle();
    }
}

public sealed class DcSyncRuleTests
{
    private readonly DcSyncRule _sut = new();

    [Fact]
    public void Produces_a_golden_ticket_path()
    {
        var corpus = Corpus(Finding("dcsync rights", "EVILCORP\\svc_repl", technique: "T1003.006",
            severity: Severity.Critical, tags: new[] { "dcsync" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Impact.Should().Be(Severity.Critical);
        path.Phase.Should().Be(MissionPhase.PrivilegeEscalation);
        path.Steps.Should().Contain(s => s.Technique == "T1558.001");
    }
}

public sealed class UnconstrainedDelegationRuleTests
{
    private readonly UnconstrainedDelegationRule _sut = new();

    [Fact]
    public void Builds_coerce_capture_dcsync_chain()
    {
        var corpus = Corpus(Finding("unconstrained", "WEB01$", severity: Severity.Critical,
            tags: new[] { "unconstrained-delegation" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Hops.Should().Be(3);
        path.Steps.Last().Technique.Should().Be("T1003.006");
    }
}

public sealed class MalwareTriageRuleTests
{
    private readonly MalwareTriageRule _sut = new();

    [Fact]
    public void Fuses_keys_and_c2_into_one_decrypt_and_scope_path()
    {
        var corpus = Corpus(
            Finding("Dridex sample", "hash", AssetDomain.Endpoint, technique: "T1005",
                properties: new Dictionary<string, string> { ["family"] = "Dridex" },
                tags: new[] { "malware", "triage", "banking-trojan" }),
            Finding("rc4 key", "Dridex", AssetDomain.Endpoint,
                properties: new Dictionary<string, string> { ["family"] = "Dridex", ["keyType"] = "rc4" },
                tags: new[] { "crypto-key" }),
            Finding("c2", "185.99.4.10:443", AssetDomain.Network,
                properties: new Dictionary<string, string> { ["family"] = "Dridex" },
                tags: new[] { "c2-infra" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Phase.Should().Be(MissionPhase.MalwareTriage);
        path.Confidence.Should().Be(Confidence.Confirmed);
        path.Steps.Should().HaveCount(3); // confirm + decrypt + scope
        path.Rationale.Should().Contain("decrypt");
    }

    [Fact]
    public void Sample_without_loot_still_yields_a_recover_config_path()
    {
        var corpus = Corpus(Finding("Unknown sample", "hash", AssetDomain.Endpoint,
            properties: new Dictionary<string, string> { ["family"] = "Unknown" },
            tags: new[] { "malware", "triage" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Steps.Should().HaveCount(1);
    }
}

public sealed class ExfiltrationRuleTests
{
    private readonly ExfiltrationRule _sut = new();

    [Fact]
    public void Builds_identify_and_contain_path()
    {
        var corpus = Corpus(Finding("Large outbound transfer", "10.20.5.9", AssetDomain.Network,
            severity: Severity.Critical,
            properties: new Dictionary<string, string> { ["src_ip"] = "10.20.5.9", ["dest_ip"] = "185.99.4.10" },
            tags: new[] { "exfiltration" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Phase.Should().Be(MissionPhase.DataExfiltration);
        path.Steps.Should().HaveCount(2);
        path.Objective.Should().Contain("targeted records");
    }

    [Fact]
    public void Notes_alignment_with_known_c2_channel()
    {
        var corpus = Corpus(
            Finding("exfil", "10.20.5.9", AssetDomain.Network,
                properties: new Dictionary<string, string> { ["src_ip"] = "10.20.5.9" },
                tags: new[] { "exfiltration" }),
            Finding("beacon", "10.20.5.9", AssetDomain.Network, tags: new[] { "c2-beacon" }));

        _sut.Evaluate(corpus).Single().Rationale.Should().Contain("C2 channel");
    }
}
