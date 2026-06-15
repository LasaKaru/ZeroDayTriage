using FluentAssertions;
using ZeroDayTriage.Tools.Normalizers;
using Xunit;

namespace ZeroDayTriage.Tools.Tests;

public sealed class NormalizerRegistryTests
{
    private readonly NormalizerRegistry _sut = NormalizerRegistry.CreateDefault();

    [Theory]
    [InlineData(nameof(Fixtures.BloodHoundUsers), "sharphound")]
    [InlineData(nameof(Fixtures.NetExec), "netexec")]
    [InlineData(nameof(Fixtures.Certipy), "certipy")]
    [InlineData(nameof(Fixtures.Slither), "slither")]
    public void Resolve_routes_payload_to_correct_normalizer(string fixtureName, string expectedSource)
    {
        var payload = LookupFixture(fixtureName);

        _sut.Resolve(payload)!.Source.Should().Be(expectedSource);
    }

    [Fact]
    public void Normalize_with_unknown_payload_returns_empty()
    {
        _sut.Normalize("this matches nothing").Should().BeEmpty();
    }

    [Fact]
    public void Normalize_honors_explicit_source_hint()
    {
        var findings = _sut.Normalize(Fixtures.Certipy, source: "certipy");

        findings.Should().NotBeEmpty();
        findings.Should().OnlyContain(f => f.Source == "certipy");
    }

    [Fact]
    public void CreateDefault_registers_every_builtin_normalizer()
    {
        _sut.Normalizers.Select(n => n.Source)
            .Should().BeEquivalentTo(new[]
            {
                "sharphound", "netexec", "certipy", "slither", "suricata", "rita", "malware-config",
            });
    }

    private static string LookupFixture(string name) => name switch
    {
        nameof(Fixtures.BloodHoundUsers) => Fixtures.BloodHoundUsers,
        nameof(Fixtures.NetExec) => Fixtures.NetExec,
        nameof(Fixtures.Certipy) => Fixtures.Certipy,
        nameof(Fixtures.Slither) => Fixtures.Slither,
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };
}
