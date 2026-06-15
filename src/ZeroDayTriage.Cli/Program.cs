using ZeroDayTriage.Cli;
using ZeroDayTriage.Cli.Rendering;
using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Reasoning;
using ZeroDayTriage.Storage;
using ZeroDayTriage.Tools.Collection;
using ZeroDayTriage.Tools.Execution;
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
                "collect" => await CollectAsync(rest),
                "run" => await RunToolAsync(args),
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
        var dbPath = args.Get("db", "zerodaytriage.db")!;
        var source = args.Get("source");
        var registry = NormalizerRegistry.CreateDefault();

        // Pipe mode: `nxc smb ... | ztriage ingest --stdin --source netexec`
        if (args.Has("stdin"))
        {
            var piped = await Console.In.ReadToEndAsync();
            var store2 = SqliteFindingStore.ForFile(dbPath);
            await store2.InitializeAsync();
            var f = registry.Normalize(piped, source);
            var newCount = await store2.UpsertAsync(f);
            Console.WriteLine($"ingested {f.Count} finding(s) from stdin via {source ?? registry.Resolve(piped)?.Source ?? "none"}; {newCount} new, stored in {dbPath}");
            return f.Count == 0 ? 2 : 0;
        }

        var input = args.Get("input")
            ?? throw new ArgumentException("--input <file|dir> (or --stdin) is required");
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

    private static async Task<int> CollectAsync(ArgMap args)
    {
        var target = args.Get("target")
            ?? throw new ArgumentException("--target <host|ip> is required");
        var dbPath = args.Get("db", "zerodaytriage.db")!;

        var context = new TargetContext
        {
            Target = target,
            Domain = args.Get("domain"),
            Username = args.Get("user"),
            Password = args.Get("password"),
            NtlmHash = args.Get("hash"),
            DcIp = args.Get("dc-ip"),
        };

        var settings = new ToolSettings
        {
            LauncherPrefix = args.Get("launcher"),
            DryRun = args.Has("dry-run"),
            Timeout = TimeSpan.FromSeconds(args.GetInt("timeout", 300)),
            CommandOverrides = BuildCommandOverrides(args),
        };

        var orchestrator = ToolOrchestrator.CreateDefault(new ProcessRunner());
        Console.WriteLine($"collecting from {target} (domain={context.Domain ?? "-"}, user={context.Username ?? "-"}){(settings.DryRun ? " [DRY RUN]" : "")}");

        var results = await orchestrator.CollectAsync(context, settings);
        foreach (var r in results)
        {
            if (!r.Executed)
            {
                Console.WriteLine($"  {r.Tool}: {(settings.DryRun ? r.Command : r.Error)}");
                continue;
            }

            var status = r.Error is null ? "ok" : $"warning: {r.Error}";
            Console.WriteLine($"  {r.Tool}: {r.Findings.Count} finding(s) [{status}]");
            Console.WriteLine($"    $ {r.Command}");
        }

        if (settings.DryRun)
        {
            return 0;
        }

        var all = ToolOrchestrator.AllFindings(results);
        var store = SqliteFindingStore.ForFile(dbPath);
        await store.InitializeAsync();
        var inserted = await store.UpsertAsync(all);
        Console.WriteLine($"collected {all.Count} finding(s); {inserted} new, stored in {dbPath}");
        Console.WriteLine($"next: ztriage triage --db {dbPath}");
        return 0;
    }

    private static async Task<int> RunToolAsync(string[] fullArgs)
    {
        // ztriage run --as <tool> --db <db> -- <command and its args...>
        var sep = Array.IndexOf(fullArgs, "--");
        if (sep < 0 || sep == fullArgs.Length - 1)
        {
            Console.Error.WriteLine("usage: ztriage run [--as <tool>] [--db <db>] -- <command> [args...]");
            Console.Error.WriteLine("  e.g. ztriage run --as netexec -- nxc smb 10.0.0.5 -u jdoe -p Passw0rd");
            return 1;
        }

        var opts = new ArgMap(fullArgs[1..sep]);
        var commandParts = fullArgs[(sep + 1)..];
        var source = opts.Get("as");
        var dbPath = opts.Get("db", "zerodaytriage.db")!;
        var timeout = TimeSpan.FromSeconds(opts.GetInt("timeout", 300));

        var fileName = commandParts[0];
        var commandArgs = commandParts[1..];

        Console.WriteLine($"running: {string.Join(' ', commandParts)}");
        var result = await new ProcessRunner().RunAsync(fileName, commandArgs, timeout: timeout);
        var raw = string.Concat(result.StandardOutput, "\n", result.StandardError);

        if (result.TimedOut)
        {
            Console.Error.WriteLine($"command timed out after {timeout}");
        }

        var registry = NormalizerRegistry.CreateDefault();
        var findings = registry.Normalize(raw, source);
        var resolved = source ?? registry.Resolve(raw)?.Source ?? "none";

        var store = SqliteFindingStore.ForFile(dbPath);
        await store.InitializeAsync();
        var inserted = await store.UpsertAsync(findings);
        Console.WriteLine($"parsed {findings.Count} finding(s) via {resolved}; {inserted} new, stored in {dbPath}");
        if (findings.Count == 0)
        {
            Console.WriteLine("  (no findings — check --as matches the tool, or inspect the raw output)");
        }

        return 0;
    }

    private static IReadOnlyDictionary<string, string> BuildCommandOverrides(ArgMap args)
    {
        var overrides = new Dictionary<string, string>();
        if (args.Get("netexec-command") is { } nxc)
        {
            overrides["netexec"] = nxc;
        }

        if (args.Get("certipy-command") is { } certipy)
        {
            overrides["certipy"] = certipy;
        }

        return overrides;
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

            COMMANDS (live / real data):
              collect --target <ip>     Run the tools against a live target and store real findings.
              run -- <command...>       Execute ANY tool command and normalize its real output.
              ingest --stdin            Pipe a tool's real output straight in.
              ingest  --input <path>    Normalize saved tool output (file or dir) into the DB.
              triage                    Reason over stored findings and emit a prioritized report.
              list                      List findings currently in the database.

            COMMANDS (offline demo):
              demo                      Run the built-in EVIL CORP SAMPLE scenario (not a real target).

            COMMON OPTIONS:
              --db <path>               SQLite database path (default: zerodaytriage.db)
              --format console|markdown|json
              --top <n>                 How many attack paths to show (default: 5)
              --source / --as <name>    Force a normalizer (sharphound|netexec|certipy|slither|suricata|rita|malware-config)

            COLLECT OPTIONS:
              --target <host|ip>        Target host/IP (required)
              --domain <fqdn>           AD domain
              --user / --password       Credentials, or --hash <LM:NT> for pass-the-hash
              --dc-ip <ip>              Domain controller IP (needed by certipy)
              --launcher "wsl"          Prefix every tool with a launcher (run Linux tools from Windows)
              --dry-run                 Print the exact commands without executing them
              --netexec-command / --certipy-command   Override a tool's binary/path

            EXAMPLES (real engagement):
              ztriage collect --target 10.10.0.5 --domain evilcorp.local \
                       --user jdoe --password 'Passw0rd!' --dc-ip 10.10.0.5 --db eng.db
              ztriage collect --target 10.10.0.5 --user jdoe --password p --launcher wsl --dry-run
              nxc smb 10.10.0.5 -u jdoe -p p | ztriage ingest --stdin --source netexec --db eng.db
              ztriage run --as certipy -- certipy find -u jdoe@evilcorp.local -p p -dc-ip 10.10.0.5 -stdout -json
              ztriage triage --db eng.db --format markdown --output report.md
            """);
    }
}
