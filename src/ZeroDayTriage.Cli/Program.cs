using ZeroDayTriage.Cli;
using ZeroDayTriage.Cli.Rendering;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning;
using ZeroDayTriage.Storage;
using ZeroDayTriage.Tools.Normalizers;

return await Cli.RunAsync(args);

internal static class Cli
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintHelp();
            return 0;
        }

        var command = args[0].ToLowerInvariant();
        var rest = new ArgMap(args.Skip(1));

        try
        {
            return command switch
            {
                "demo" => await DemoAsync(rest),
                "ingest" => await IngestAsync(rest),
                "triage" => await TriageAsync(rest),
                "list" => await ListAsync(rest),
                _ => Unknown(command),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static Task<int> DemoAsync(ArgMap args)
    {
        var format = ParseFormat(args.Get("format", "console"));
        var top = args.GetInt("top", 5);

        var engine = ReasoningEngine.CreateDefault();
        var report = engine.Triage(SampleData.EvilCorp());
        Console.WriteLine(ReportRenderer.Render(report, format, top));
        return Task.FromResult(0);
    }

    private static async Task<int> IngestAsync(ArgMap args)
    {
        var input = args.Get("input")
            ?? throw new ArgumentException("--input <file|dir> is required");
        var dbPath = args.Get("db", "zerodaytriage.db")!;
        var source = args.Get("source");

        var registry = NormalizerRegistry.CreateDefault();
        var files = ResolveInputFiles(input);
        if (files.Count == 0)
        {
            Console.Error.WriteLine($"no input files found at '{input}'");
            return 1;
        }

        var store = SqliteFindingStore.ForFile(dbPath);
        await store.InitializeAsync();

        var all = new List<Finding>();
        foreach (var file in files)
        {
            var content = await File.ReadAllTextAsync(file);
            var normalizer = source is not null ? source : registry.Resolve(content)?.Source ?? "none";
            var findings = registry.Normalize(content, source);
            all.AddRange(findings);
            Console.WriteLine($"  {Path.GetFileName(file)}: {findings.Count} finding(s) via {normalizer}");
        }

        var inserted = await store.UpsertAsync(all);
        Console.WriteLine($"ingested {all.Count} finding(s); {inserted} new, stored in {dbPath}");
        return 0;
    }

    private static async Task<int> TriageAsync(ArgMap args)
    {
        var dbPath = args.Get("db", "zerodaytriage.db")!;
        var format = ParseFormat(args.Get("format", "console"));
        var top = args.GetInt("top", 5);
        var output = args.Get("output");

        var store = SqliteFindingStore.ForFile(dbPath);
        await store.InitializeAsync();
        var findings = await store.GetAllAsync();

        var report = ReasoningEngine.CreateDefault().Triage(findings);
        var rendered = ReportRenderer.Render(report, format, top);

        if (output is not null)
        {
            await File.WriteAllTextAsync(output, rendered);
            Console.WriteLine($"wrote report to {output}");
        }
        else
        {
            Console.WriteLine(rendered);
        }

        return 0;
    }

    private static async Task<int> ListAsync(ArgMap args)
    {
        var dbPath = args.Get("db", "zerodaytriage.db")!;
        var store = SqliteFindingStore.ForFile(dbPath);
        await store.InitializeAsync();
        var findings = await store.GetAllAsync();

        Console.WriteLine($"{findings.Count} finding(s) in {dbPath}:");
        foreach (var f in findings.OrderByDescending(f => f.Severity))
        {
            Console.WriteLine($"  [{f.Severity,-8}] {f.Domain,-15} {f.Title}  ({f.Source})");
        }

        return 0;
    }

    private static IReadOnlyList<string> ResolveInputFiles(string input)
    {
        if (File.Exists(input))
        {
            return new[] { input };
        }

        if (Directory.Exists(input))
        {
            return Directory.GetFiles(input, "*", SearchOption.AllDirectories)
                .Where(f => f.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                    || f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                    || f.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
                .OrderBy(f => f)
                .ToList();
        }

        return Array.Empty<string>();
    }

    private static ReportFormat ParseFormat(string? value) => value?.ToLowerInvariant() switch
    {
        "json" => ReportFormat.Json,
        "markdown" or "md" => ReportFormat.Markdown,
        _ => ReportFormat.Console,
    };

    private static bool IsHelp(string arg) =>
        arg is "-h" or "--help" or "help";

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"unknown command '{command}'");
        PrintHelp();
        return 1;
    }

    private static void PrintHelp()
    {
        Console.WriteLine(
            """
            ztriage — Project ZeroDay 2026 orchestration & AI-triage layer

            USAGE:
              ztriage <command> [options]

            COMMANDS:
              demo                      Run the built-in EVIL CORP scenario through the engine.
              ingest  --input <path>    Normalize tool output (file or dir) into the findings DB.
              triage                    Reason over stored findings and emit a prioritized report.
              list                      List findings currently in the database.

            COMMON OPTIONS:
              --db <path>               SQLite database path (default: zerodaytriage.db)
              --format console|markdown|json
              --top <n>                 How many attack paths to show (default: 5)
              --source <name>           Force a normalizer (sharphound|netexec|certipy|slither)
              --input <file|dir>        Tool output to ingest
              --output <file>           Write the rendered report to a file

            EXAMPLES:
              ztriage demo --format markdown
              ztriage ingest --input ./loot/ --db engagement.db
              ztriage triage --db engagement.db --format markdown --output report.md
            """);
    }
}
