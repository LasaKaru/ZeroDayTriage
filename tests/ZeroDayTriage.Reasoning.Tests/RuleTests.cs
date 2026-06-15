using FluentAssertions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning.Rules;
using Xunit;
using static ZeroDayTriage.Reasoning.Tests.Builders;

namespace ZeroDayTriage.Reasoning.Tests;

public sealed class KerberoastingRuleTests
{
    private readonly KerberoastingRule _sut = new();

    [Fact]
    public void Emits_a_path_for_each_kerberoastable_account()
    {
        var corpus = Corpus(Kerberoastable("SVC_SQL"), Kerberoastable("SVC_WEB"));

        _sut.Evaluate(corpus).Should().HaveCount(2);
    }

    [Fact]
    public void Fuses_genericwrite_on_the_same_principal_into_a_critical_chain()
    {
        var corpus = Corpus(Kerberoastable("SVC_SQL"), GenericWrite("SVC_SQL", "OU=Servers"));

        var path = _sut.Evaluate(corpus).Single();

        path.Impact.Should().Be(Severity.Critical);
        path.Hops.Should().Be(3);
        path.Rationale.Should().Contain("GenericWrite");
        path.Steps.Should().Contain(s => s.EvidenceFindingIds.Count > 0);
    }

    [Fact]
    public void Plain_roastable_account_stays_high_not_critical()
    {
        var corpus = Corpus(Kerberoastable("SVC_SQL"));

        _sut.Evaluate(corpus).Single().Impact.Should().Be(Severity.High);
    }

    [Fact]
    public void Skips_findings_without_a_principal()
    {
        var corpus = Corpus(Finding("roastable no principal", principal: null, tags: "kerberoastable"));

        _sut.Evaluate(corpus).Should().BeEmpty();
    }
}

public sealed class AdcsEscalationRuleTests
{
    private readonly AdcsEscalationRule _sut = new();

    [Fact]
    public void Builds_a_three_step_critical_path_to_domain_admin()
    {
        var corpus = Corpus(Finding("ESC1", "BankUserAuth", technique: "T1649",
            properties: new Dictionary<string, string> { ["template"] = "BankUserAuth", ["esc"] = "ESC1" },
            tags: new[] { "adcs", "esc1" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Impact.Should().Be(Severity.Critical);
        path.Hops.Should().Be(3);
        path.Steps.Last().Technique.Should().Be("T1003.006");
    }
}

public sealed class AclEscalationRuleTests
{
    private readonly AclEscalationRule _sut = new();

    [Fact]
    public void Chains_to_dcsync_when_the_target_can_replicate()
    {
        var corpus = Corpus(
            GenericWrite("LOWPRIV", "DA_SVC"),
            Finding("dcsync", "DA_SVC", technique: "T1003.006", severity: Severity.Critical, tags: "dcsync"));

        var path = _sut.Evaluate(corpus).First(p => p.Name.Contains("DA_SVC"));

        path.Impact.Should().Be(Severity.Critical);
        path.Objective.Should().Contain("Domain compromise");
        path.Steps.Should().Contain(s => s.Technique == "T1003.006");
    }

    [Fact]
    public void Does_not_emit_duplicate_paths_for_the_same_ace()
    {
        var corpus = Corpus(GenericWrite("LOWPRIV", "TARGET"));

        _sut.Evaluate(corpus).Should().ContainSingle();
    }
}

public sealed class PassTheHashRuleTests
{
    private readonly PassTheHashRule _sut = new();

    [Fact]
    public void Local_admin_promotes_to_critical_with_dump_step()
    {
        var corpus = Corpus(Finding("admin", "EVILCORP\\backupadmin", severity: Severity.Critical,
            properties: new Dictionary<string, string> { ["host"] = "FS01" },
            tags: new[] { "pass-the-hash", "local-admin" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Impact.Should().Be(Severity.Critical);
        path.Hops.Should().Be(2);
    }

    [Fact]
    public void Non_admin_hash_is_high_single_step()
    {
        var corpus = Corpus(Finding("user", "EVILCORP\\jdoe",
            properties: new Dictionary<string, string> { ["host"] = "WS01" },
            tags: new[] { "pass-the-hash" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Impact.Should().Be(Severity.High);
        path.Hops.Should().Be(1);
    }
}

public sealed class CoercionRelayRuleTests
{
    private readonly CoercionRelayRule _sut = new();

    [Fact]
    public void Escalates_to_esc8_when_adcs_present()
    {
        var corpus = Corpus(
            Finding("no signing", "DC01", severity: Severity.Medium, tags: "relay-target"),
            Finding("ESC1", "Tmpl", tags: new[] { "adcs", "esc1" }));

        var path = _sut.Evaluate(corpus).Single();

        path.Name.Should().Contain("ESC8");
        path.Impact.Should().Be(Severity.Critical);
    }

    [Fact]
    public void No_relay_target_means_no_path()
    {
        var corpus = Corpus(Finding("ESC1", "Tmpl", tags: new[] { "adcs", "esc1" }));

        _sut.Evaluate(corpus).Should().BeEmpty();
    }
}

public sealed class SmartContractRuleTests
{
    private readonly SmartContractRule _sut = new();

    [Fact]
    public void Promotes_high_impact_reentrancy()
    {
        var corpus = Corpus(Finding("reentrancy", "VaultBank.withdraw()", domain: AssetDomain.SmartContract,
            severity: Severity.Critical,
            properties: new Dictionary<string, string> { ["check"] = "reentrancy-eth", ["impact"] = "High" },
            tags: new[] { "smart-contract", "reentrancy-eth" }));

        _sut.Evaluate(corpus).Should().ContainSingle(p => p.Domain == AssetDomain.SmartContract);
    }

    [Fact]
    public void Ignores_low_severity_cosmetic_findings()
    {
        var corpus = Corpus(Finding("naming", "C", domain: AssetDomain.SmartContract, severity: Severity.Low,
            properties: new Dictionary<string, string> { ["check"] = "naming-convention" },
            tags: new[] { "smart-contract" }));

        _sut.Evaluate(corpus).Should().BeEmpty();
    }
}
