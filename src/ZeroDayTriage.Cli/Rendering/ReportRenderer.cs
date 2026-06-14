using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Cli.Rendering;

public enum ReportFormat
{
    Console,
    Markdown,
    Json,
}

/// <summary>Renders a <see cref="TriageReport"/> for the operator in console, Markdown, or JSON.</summary>
public static class ReportRenderer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Render(TriageReport report, ReportFormat format, int top = 5) => format switch
    {
        ReportFormat.Json => JsonSerializer.Serialize(report, JsonOptions),
        ReportFormat.Markdown => RenderMarkdown(report, top),
        _ => RenderConsole(report, top),
    };

    private static string RenderConsole(TriageReport report, int top)
    {
        var sb = new StringBuilder();
        sb.AppendLine("==================================================================");
        sb.AppendLine("  PROJECT ZERODAY 2026 — TRIAGE REPORT");
        sb.AppendLine($"  generated {report.GeneratedAt:u}  |  {report.FindingsConsidered} findings considered");
        sb.AppendLine("==================================================================");
        sb.AppendLine();

        if (report.TopPath is { } top1)
        {
            sb.AppendLine($"  >> NEXT ACTION (score {top1.Score:F1}): {top1.Name}");
            sb.AppendLine($"     {top1.Rationale}");
            sb.AppendLine();
        }
        else
        {
            sb.AppendLine("  No actionable attack paths derived from the current findings.");
            sb.AppendLine();
        }

        var rank = 1;
        foreach (var path in report.Paths.Take(top))
        {
            sb.AppendLine($"  [{rank}] {path.Name}   (score {path.Score:F1} | {path.Impact} | {path.Confidence} | {path.Hops} hop(s))");
            sb.AppendLine($"      objective : {path.Objective}");
            sb.AppendLine($"      why       : {path.Rationale}");
            var stepNo = 1;
            foreach (var step in path.Steps)
            {
                sb.AppendLine($"        {stepNo}. [{step.Phase}] {step.Action}");
                sb.AppendLine($"           $ {step.Tooling}");
                stepNo++;
            }

            sb.AppendLine();
            rank++;
        }

        if (report.SuppressedAsNoise.Count > 0)
        {
            sb.AppendLine($"  Suppressed as noise ({report.SuppressedAsNoise.Count}):");
            foreach (var n in report.SuppressedAsNoise.Take(10))
            {
                sb.AppendLine($"    - {n}");
            }

            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string RenderMarkdown(TriageReport report, int top)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Project ZeroDay 2026 — Triage Report");
        sb.AppendLine();
        sb.AppendLine($"- **Generated:** {report.GeneratedAt:u}");
        sb.AppendLine($"- **Findings considered:** {report.FindingsConsidered}");
        if (report.TopPath is { } t)
        {
            sb.AppendLine($"- **Recommended next action:** {t.Name} _(score {t.Score:F1})_");
        }

        sb.AppendLine();

        if (report.FindingsByDomain.Count > 0)
        {
            sb.AppendLine("## Findings by domain");
            sb.AppendLine();
            sb.AppendLine("| Domain | Count |");
            sb.AppendLine("| ------ | ----: |");
            foreach (var kvp in report.FindingsByDomain.OrderByDescending(k => k.Value))
            {
                sb.AppendLine($"| {kvp.Key} | {kvp.Value} |");
            }

            sb.AppendLine();
        }

        sb.AppendLine("## Prioritized attack paths");
        sb.AppendLine();
        var rank = 1;
        foreach (var path in report.Paths.Take(top))
        {
            sb.AppendLine($"### {rank}. {path.Name}  ·  score {path.Score:F1}");
            sb.AppendLine();
            sb.AppendLine($"- **Objective:** {path.Objective}");
            sb.AppendLine($"- **Impact / Confidence:** {path.Impact} / {path.Confidence}");
            sb.AppendLine($"- **Rationale:** {path.Rationale}");
            sb.AppendLine();
            var stepNo = 1;
            foreach (var step in path.Steps)
            {
                sb.AppendLine($"{stepNo}. _({step.Phase})_ {step.Action}");
                sb.AppendLine($"   ```");
                sb.AppendLine($"   {step.Tooling}");
                sb.AppendLine($"   ```");
                stepNo++;
            }

            sb.AppendLine();
            rank++;
        }

        return sb.ToString();
    }
}
