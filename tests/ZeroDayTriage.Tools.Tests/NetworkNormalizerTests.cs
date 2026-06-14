using FluentAssertions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Tools.Normalizers;
using Xunit;

namespace ZeroDayTriage.Tools.Tests;

public sealed class SuricataNormalizerTests
{
    private readonly SuricataNormalizer _sut = new();

    [Fact]
    public void Classifies_socgholish_as_initial_access()
    {
        var findings = _sut.Parse(Fixtures.SuricataEve);

        findings.Should().Contain(f =>
            f.Phase == MissionPhase.InitialAccess &&
            f.HasTag("initial-access") &&
            f.Title.Contains("SocGholish"));
    }

    [Fact]
    public void Classifies_cobalt_strike_as_command_and_control()
    {
        var findings = _sut.Parse(Fixtures.SuricataEve);

        findings.Should().Contain(f => f.Phase == MissionPhase.CommandAndControl && f.HasTag("c2-beacon"));
    }

    [Fact]
    public void Classifies_large_outbound_as_exfiltration()
    {
        var findings = _sut.Parse(Fixtures.SuricataEve);

        findings.Should().Contain(f => f.Phase == MissionPhase.DataExfiltration && f.HasTag("exfiltration"));
    }

    [Fact]
    public void Maps_severity_one_to_critical()
    {
        var findings = _sut.Parse(Fixtures.SuricataEve);

        findings.First(f => f.Title.Contains("SocGholish")).Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Ignores_non_alert_events()
    {
        var findings = _sut.Parse(Fixtures.SuricataEve);

        // The flow event (4th line) must not produce a finding; only the 3 alerts do.
        findings.Should().HaveCount(3);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not ndjson")]
    [InlineData("{ broken json")]
    public void Parse_never_throws_on_garbage(string input)
    {
        var act = () => _sut.Parse(input);
        act.Should().NotThrow();
    }

    [Fact]
    public void CanParse_detects_eve_alerts()
    {
        _sut.CanParse(Fixtures.SuricataEve).Should().BeTrue();
        _sut.CanParse(Fixtures.BloodHoundUsers).Should().BeFalse();
    }
}

public sealed class BeaconAnalysisNormalizerTests
{
    private readonly BeaconAnalysisNormalizer _sut = new();

    [Fact]
    public void Strong_beacon_is_critical_and_confirmed()
    {
        var findings = _sut.Parse(Fixtures.RitaBeacons);

        var strong = findings.Single(f => f.Property("source") == "10.20.1.44");
        strong.Severity.Should().Be(Severity.Critical);
        strong.Confidence.Should().Be(Confidence.Confirmed);
        strong.Phase.Should().Be(MissionPhase.CommandAndControl);
    }

    [Fact]
    public void Weak_beacon_is_downgraded()
    {
        var findings = _sut.Parse(Fixtures.RitaBeacons);

        var weak = findings.Single(f => f.Property("source") == "10.20.2.7");
        weak.Severity.Should().Be(Severity.High);
        weak.Confidence.Should().Be(Confidence.Probable);
    }

    [Fact]
    public void CanParse_requires_beacon_and_score()
    {
        _sut.CanParse(Fixtures.RitaBeacons).Should().BeTrue();
        _sut.CanParse(Fixtures.NetExec).Should().BeFalse();
    }
}

public sealed class MalwareConfigNormalizerTests
{
    private readonly MalwareConfigNormalizer _sut = new();

    [Fact]
    public void Produces_a_primary_banking_trojan_finding()
    {
        var findings = _sut.Parse(Fixtures.MalwareConfig);

        findings.Should().Contain(f =>
            f.HasTag("banking-trojan") &&
            f.Phase == MissionPhase.MalwareTriage &&
            f.Severity == Severity.Critical);
    }

    [Fact]
    public void Extracts_each_cryptographic_key()
    {
        var findings = _sut.Parse(Fixtures.MalwareConfig);

        var keys = findings.Where(f => f.HasTag("crypto-key")).ToList();
        keys.Should().HaveCount(2); // rc4 + botnet_id
        keys.Should().Contain(f => f.Property("keyType") == "rc4");
    }

    [Fact]
    public void Emits_embedded_c2_as_network_iocs()
    {
        var findings = _sut.Parse(Fixtures.MalwareConfig);

        var c2 = findings.Where(f => f.HasTag("c2-infra")).ToList();
        c2.Should().HaveCount(2);
        c2.Should().OnlyContain(f => f.Domain == AssetDomain.Network && f.Phase == MissionPhase.CommandAndControl);
    }

    [Fact]
    public void Emits_host_iocs()
    {
        var findings = _sut.Parse(Fixtures.MalwareConfig);

        findings.Where(f => f.HasTag("host-artifact")).Should().HaveCount(2); // mutex + registry
    }

    [Fact]
    public void Detects_ransomware_by_capabilities()
    {
        var findings = _sut.Parse(Fixtures.RansomwareConfig);

        findings.Should().Contain(f => f.HasTag("ransomware") && f.Technique == "T1486");
    }

    [Fact]
    public void CanParse_requires_family_and_a_config_section()
    {
        _sut.CanParse(Fixtures.MalwareConfig).Should().BeTrue();
        _sut.CanParse(Fixtures.Slither).Should().BeFalse();
    }
}
