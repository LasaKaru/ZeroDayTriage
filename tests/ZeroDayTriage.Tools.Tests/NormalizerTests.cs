using FluentAssertions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Tools.Normalizers;
using Xunit;

namespace ZeroDayTriage.Tools.Tests;

public sealed class BloodHoundNormalizerTests
{
    private readonly BloodHoundNormalizer _sut = new();

    [Fact]
    public void Parses_kerberoastable_account_with_spn()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundUsers);

        findings.Should().Contain(f =>
            f.HasTag("kerberoastable") &&
            f.Principal == "SVC_SQL@EVILCORP.LOCAL" &&
            f.Severity == Severity.High &&
            f.Technique == "T1558.003");
    }

    [Fact]
    public void Parses_asrep_roastable_account()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundUsers);

        findings.Should().Contain(f => f.HasTag("asreproastable") && f.Principal!.Contains("AUDIT_SVC"));
    }

    [Fact]
    public void Extracts_dangerous_aces()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundUsers);

        findings.Should().Contain(f => f.HasTag("genericwrite") && f.Property("right") == "GenericWrite");
    }

    [Fact]
    public void Maps_getchangesall_ace_to_critical_dcsync()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundComputers);

        findings.Should().Contain(f => f.HasTag("dcsync") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Detects_unconstrained_delegation()
    {
        var findings = _sut.Parse(Fixtures.BloodHoundComputers);

        findings.Should().Contain(f => f.HasTag("unconstrained-delegation") && f.Severity == Severity.Critical);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json at all")]
    [InlineData("{ \"meta\": {}, \"data\": \"not-an-array\" }")]
    [InlineData("{ \"unterminated\": ")]
    public void Parse_never_throws_on_garbage(string input)
    {
        var act = () => _sut.Parse(input);
        act.Should().NotThrow();
        _sut.Parse(input).Should().BeEmpty();
    }

    [Fact]
    public void CanParse_recognizes_bloodhound_envelope_only()
    {
        _sut.CanParse(Fixtures.BloodHoundUsers).Should().BeTrue();
        _sut.CanParse(Fixtures.NetExec).Should().BeFalse();
        _sut.CanParse(Fixtures.Slither).Should().BeFalse();
    }

    [Fact]
    public void All_findings_carry_a_computed_id()
    {
        _sut.Parse(Fixtures.BloodHoundUsers).Should().OnlyContain(f => f.Id.Length == 16);
    }
}

public sealed class NetExecNormalizerTests
{
    private readonly NetExecNormalizer _sut = new();

    [Fact]
    public void Parses_valid_password_credential()
    {
        var findings = _sut.Parse(Fixtures.NetExec);

        findings.Should().Contain(f =>
            f.HasTag("valid-credential") &&
            f.Principal == "evilcorp.local\\svc_sql" &&
            f.Property("secretType") == "password");
    }

    [Fact]
    public void Recognizes_pass_the_hash_admin_line()
    {
        var findings = _sut.Parse(Fixtures.NetExec);

        var admin = findings.Single(f => f.Principal == "evilcorp.local\\backupadmin");
        admin.HasTag("local-admin").Should().BeTrue();
        admin.HasTag("pass-the-hash").Should().BeTrue();
        admin.Severity.Should().Be(Severity.Critical);
        admin.Property("secretType").Should().Be("ntlm");
    }

    [Fact]
    public void Detects_smb_signing_disabled()
    {
        var findings = _sut.Parse(Fixtures.NetExec);

        findings.Should().Contain(f => f.HasTag("relay-target") && f.Principal == "DC01");
    }

    [Fact]
    public void Ignores_failed_logon_lines()
    {
        var findings = _sut.Parse(Fixtures.NetExec);

        findings.Should().NotContain(f => f.Principal != null && f.Principal.Contains("jdoe"));
    }

    [Fact]
    public void CanParse_detects_console_format()
    {
        _sut.CanParse(Fixtures.NetExec).Should().BeTrue();
        _sut.CanParse(Fixtures.BloodHoundUsers).Should().BeFalse();
    }
}

public sealed class CertipyNormalizerTests
{
    private readonly CertipyNormalizer _sut = new();

    [Fact]
    public void Flags_esc1_template_as_critical()
    {
        var findings = _sut.Parse(Fixtures.Certipy);

        var esc = findings.Single();
        esc.HasTag("adcs").Should().BeTrue();
        esc.HasTag("esc1").Should().BeTrue();
        esc.Severity.Should().Be(Severity.Critical);
        esc.Property("template").Should().Be("BankUserAuth");
    }

    [Fact]
    public void Skips_templates_without_vulnerabilities()
    {
        _sut.Parse(Fixtures.Certipy).Should().HaveCount(1);
    }

    [Fact]
    public void CanParse_requires_certificate_templates_key()
    {
        _sut.CanParse(Fixtures.Certipy).Should().BeTrue();
        _sut.CanParse(Fixtures.BloodHoundUsers).Should().BeFalse();
    }
}

public sealed class SlitherNormalizerTests
{
    private readonly SlitherNormalizer _sut = new();

    [Fact]
    public void Maps_high_impact_to_critical_severity()
    {
        var findings = _sut.Parse(Fixtures.Slither);

        var reentrancy = findings.Single(f => f.Property("check") == "reentrancy-eth");
        reentrancy.Severity.Should().Be(Severity.Critical);
        reentrancy.Domain.Should().Be(AssetDomain.SmartContract);
        reentrancy.Principal.Should().Be("VaultBank.withdraw()");
    }

    [Fact]
    public void Maps_informational_to_low()
    {
        var findings = _sut.Parse(Fixtures.Slither);

        findings.Should().Contain(f => f.Property("check") == "naming-convention" && f.Severity == Severity.Low);
    }
}
