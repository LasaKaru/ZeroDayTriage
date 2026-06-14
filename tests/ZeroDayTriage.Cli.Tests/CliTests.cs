using FluentAssertions;
using ZeroDayTriage.Cli;
using ZeroDayTriage.Cli.Rendering;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning;
using Xunit;

namespace ZeroDayTriage.Cli.Tests;

public sealed class ArgMapTests
{
    [Fact]
    public void Parses_key_value_pairs()
    {
        var args = new ArgMap(new[] { "--db", "engagement.db", "--top", "3" });

        args.Get("db").Should().Be("engagement.db");
        args.GetInt("top", 5).Should().Be(3);
    }

    [Fact]
    public void Treats_trailing_token_as_bare_flag()
    {
        var args = new ArgMap(new[] { "--verbose" });

        args.Has("verbose").Should().BeTrue();
        args.Get("verbose").Should().BeNull();
    }

    [Fact]
    public void Flag_followed_by_flag_is_not_consumed_as_value()
    {
        var args = new ArgMap(new[] { "--verbose", "--db", "x.db" });

        args.Has("verbose").Should().BeTrue();
        args.Get("db").Should().Be("x.db");
    }

    [Fact]
    public void Get_returns_fallback_when_absent()
    {
        var args = new ArgMap(Array.Empty<string>());

        args.Get("db", "default.db").Should().Be("default.db");
        args.GetInt("top", 5).Should().Be(5);
    }

    [Fact]
    public void Keys_are_case_insensitive()
    {
        var args = new ArgMap(new[] { "--DB", "x" });

        args.Get("db").Should().Be("x");
    }
}

public sealed class SampleDataTests
{
    [Fact]
    public void EvilCorp_scenario_is_internally_consistent()
    {
        var findings = SampleData.EvilCorp();

        findings.Should().NotBeEmpty();
        findings.Should().OnlyContain(f => f.Id.Length == 16);
        findings.Select(f => f.Id).Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void EvilCorp_triages_to_the_adcs_path_first()
    {
        var report = ReasoningEngine.CreateDefault().Triage(SampleData.EvilCorp());

        report.TopPath.Should().NotBeNull();
        report.TopPath!.Name.Should().Contain("ESC1");
        report.SuppressedAsNoise.Should().NotBeEmpty();
    }
}

public sealed class ReportRendererTests
{
    private static TriageReport Report() =>
        ReasoningEngine.CreateDefault().Triage(SampleData.EvilCorp());

    [Fact]
    public void Console_render_contains_next_action_banner()
    {
        var text = ReportRenderer.Render(Report(), ReportFormat.Console);

        text.Should().Contain("PROJECT ZERODAY 2026");
        text.Should().Contain("NEXT ACTION");
    }

    [Fact]
    public void Markdown_render_is_valid_markdown_with_headers()
    {
        var text = ReportRenderer.Render(Report(), ReportFormat.Markdown);

        text.Should().Contain("# Project ZeroDay 2026");
        text.Should().Contain("## Prioritized attack paths");
        text.Should().Contain("| Domain | Count |");
    }

    [Fact]
    public void Json_render_is_machine_parseable()
    {
        var text = ReportRenderer.Render(Report(), ReportFormat.Json);

        var act = () => System.Text.Json.JsonDocument.Parse(text);
        act.Should().NotThrow();
        text.Should().Contain("\"paths\"");
    }

    [Fact]
    public void Top_parameter_limits_rendered_paths()
    {
        var oneOnly = ReportRenderer.Render(Report(), ReportFormat.Markdown, top: 1);

        oneOnly.Should().Contain("### 1.");
        oneOnly.Should().NotContain("### 2.");
    }
}
